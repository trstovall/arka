
from __future__ import annotations
from typing import Generator, Callable
from arka import broker
from collections import deque
from os import urandom
from sys import platform

import types
import asyncio
import time
import struct
import socket
import heapq
import random


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

    # EOF, gracefully close connection after peer sends NONE
    NONE = b'\xfd'

    # Ignored, but planned conditional responses
    EXT = b'\xfe'

    # Ignored, but planned conditional responses
    ERROR = b'\xff'


# Type aliases
Address = tuple[str, int]
Message = bytes
Datagram = bytes
MessageList = bytes
EventQueue = asyncio.Queue[broker.AbstractBrokerEvent]

class AbstractMessageEvent(object):
    def __init__(self, msg: Message):
        pass

MessageQueue = asyncio.Queue[broker.AbstractBrokerEvent | AbstractMessageEvent]


### Helpers

def seq_lt(a: int, b: int) -> bool:
    return (a - b) & 0xffffffff > 0x8fffffff

def seq_le(a: int, b: int) -> bool:
    return a == b or seq_lt(a, b)

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

def parse_mlen(x: bytes, pos: int = 0) -> tuple[int, int] | None:
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

def msg_peers_sub(active: bool = True) -> Message:
    return MSG.PEERS_SUB + int(active).to_bytes(1, 'little')

def msg_peers_pub(
        added: set[Address] = set(), removed: set[Address] = set()
) -> Message:
    msg_type = MSG.PEERS_PUB
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

def msg_peers_req(neighbor: Address) -> Message:
    return MSG.PEERS_REQ + addr_to_bytes(neighbor)

def msg_peers_res(neighbor: Address) -> Message:
    return MSG.PEERS_RES + addr_to_bytes(neighbor)


### Message deserializers

class MsgToSend(AbstractMessageEvent):

    def __init__(self, msg: Message):
        self.msg = msg


class MsgPeersSub(AbstractMessageEvent):

    def __init__(self, msg: Message):
        # self.active
        self.active = bool(msg[1] & 1)


class MsgPeersPub(AbstractMessageEvent):

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
        else:
            num_removed = msg[offset] >> 1
            offset += 1
        if len(msg) != offset + 18 * (num_added + num_removed):
            raise ValueError('Invalid message size.')
        start, end = offset, offset + 18 * num_added
        # self.added
        self.added: set[Address] = {
            bytes_to_addr(msg[i:i+18]) for i in range(start, end, 18)
        }
        start, end = end, end + 18 * num_removed
        # self.removed
        self.removed: set[Address] = {
            bytes_to_addr(msg[i:i+18]) for i in range(start, end, 18)
        }


class MsgPeersReq(AbstractMessageEvent):

    def __init__(self, msg: Message):
        if len(msg) != 19:
            raise ValueError('Invalid message size.')
        # self.neighbor
        self.neighbor: Address = bytes_to_addr(msg[1:])


class MsgPeersRes(AbstractMessageEvent):

    def __init__(self, msg: Message):
        if len(msg) != 19:
            raise ValueError('Invalid message size.')
        # self.neighbor
        self.neighbor: Address = bytes_to_addr(msg[1:])


DESERIALIZE: dict[bytes, type[AbstractMessageEvent]] = {
    MSG.PEERS_SUB: MsgPeersSub,
    MSG.PEERS_PUB: MsgPeersPub,
    MSG.PEERS_REQ: MsgPeersReq,
    MSG.PEERS_RES: MsgPeersRes,

    # MSG.TX_SUB: MsgTxSub,
    # MSG.TX_PUB: MsgTxPub,
    # MSG.TX_REQ: MsgTxReq,
    # MSG.TX_RES: MsgTxRes,

    # MSG.BLOCK_SUB: MsgBlockSub,
    # MSG.BLOCK_PUB: MsgBlockPub,
    # MSG.BLOCK_REQ: MsgBlockReq,
    # MSG.BLOCK_RES: MsgBlockRes,

    # MSG.TIP_SUB: MsgTipSub,
    # MSG.TIP_PUB: MsgTipPub,
    # MSG.TIP_REQ: MsgTipReq,
    # MSG.TIP_RES: MsgTipRes,
    
    # MSG.WORK_SUB: MsgWorkSub,
    # MSG.WORK_PUB: MsgWorkPub,
    # MSG.WORK_REQ: MsgWorkReq,
    # MSG.WORK_RES: MsgWorkRes,

    # MSG.NONE: MsgNone
}


### Socket

class Socket(object):

    # State
    STATE_NEW = 0
    STATE_SYN = 1
    STATE_SYN_ACK = 2
    STATE_ESTABLISHED = 3
    STATE_FIN = 4
    STATE_FIN_ACK = 5
    STATE_CLOSED = 6

    # Header
    HEADER = struct.Struct('<IIB')    # seq, ack, flags
    FLAG_SYN = 1
    FLAG_ACK = 2
    FLAG_FIN = 4
    MAX_SACK = 4

    # Congestion control defaults
    INITIAL_CWND = 16.0
    INITIAL_SSTHRESH = 1000.0
    MAX_ATTEMPTS = 5
    MAX_PAYLOAD = 2**10             # 1 KB
    MAX_MSG_SIZE = 2**23            # 8 MB
    MAX_READER_SIZE = 2**24 + 8     # 16 MB
    MAX_RECV_WINDOW = 2**13

    # Timers
    BACKOFF_MULTIPLIER = 1.5
    DELAYED_ACK_TO = 0.01
    KEEPALIVE_TO = 15.0
    TIMEOUT = 60.0

    def __init__(self,
        peer: Address,
        transport: asyncio.DatagramTransport,
        on_connect: Callable[[Socket], None] | None = None,
        on_close: Callable[[Socket], None] | None = None
    ):
        self.peer = peer
        self._zaddr = peer + (0, 0)
        self.transport = transport
        self.on_connect = on_connect
        self.on_close = on_close

        # state
        self._state: int = self.STATE_NEW
        self.connected: asyncio.Future[None] = asyncio.Future()
        self.closed: asyncio.Future[None] = asyncio.Future()

        # keepalive
        self._last_sent: float = time.monotonic()
        self._last_recd: float = time.monotonic()

        # sequence numbers
        self._seq: int = int.from_bytes(urandom(4), 'little')
        self._ack: int | None = None
        self._peer_ack: int | None = None
        self._last_ack_sent: int | None = None
        self._sacks: deque[tuple[int, int]] = deque(maxlen=self.MAX_SACK)

        # send/recv buffers
        self._sent: dict[int, tuple[int, float, bytes]] = {}
        self._sent_heap: list[tuple[float, int]] = []
        self._recd: dict[int, bytes] = {}
        self._reader: asyncio.StreamReader = asyncio.StreamReader()
        self._reader_len: int = 0
        self._wait_ack: int | None = None
        self._send_done: asyncio.Future[None] | None = None

        # congestion control
        self._swnd: int | None = None
        self._cwnd: float = self.INITIAL_CWND
        self._ssthresh: float = self.INITIAL_SSTHRESH
        self._last_ack_recd: int | None = None
        self._dup_ack_count: int = 0
        self._acked: asyncio.Future[None] | None = None

        # RTT + RTO
        self._srtt: float | None = None
        self._rttvar: float | None = None
        self._rto: float = 0.2      # 200 ms

        # background tasks
        self._ensure_syn_task: asyncio.Task | None = None
        self._ensure_seq_task: asyncio.Task | None = None
        self._ensure_ack_task: asyncio.Task | None = None
        self._ensure_fin_task: asyncio.Task | None = None
        self._keepalive_task: asyncio.Task | None = None

    @property
    def state(self) -> int:
        return self._state

    def connect(self) -> asyncio.Future[None]:
        if self._state == self.STATE_NEW:
            print(f'{self.peer}: NEW -> connect/SYN -> SYN')
            self._state = self.STATE_SYN
            self._ensure_syn_task = asyncio.create_task(self._ensure_syn())
        return self.connected

    def close(self) -> asyncio.Future[None]:
        match self._state:
            case self.STATE_NEW:
                print(f'{self.peer}: NEW -> close/- -> CLS')
                self._state = self.STATE_CLOSED
                self.closed.set_result(None)
                if self.on_close:
                    try:
                        self.on_close(self)
                    except Exception as e:
                        pass
            case state if state in (
                self.STATE_SYN,
                self.STATE_SYN_ACK,
                self.STATE_ESTABLISHED
            ):
                print(f'{self.peer}: * -> close/FIN -> FIN')
                self._state = self.STATE_FIN
                self._seq = (self._seq + 1) & 0xffffffff
                self._ensure_fin_task = asyncio.create_task(self._ensure_fin())
        return self.closed

    def datagram_received(self, data: Datagram):
        if self._state == self.STATE_CLOSED:
            return
        if len(data) < self.HEADER.size:
            # Close Socket on malformed packet
            print(f'{self.peer}: closed on malformed packet')
            self.close()
            return
        now = time.monotonic()
        # print(f'e: {(now - self._last_recd) * 1_000_000}')
        # Unpack header
        seq, ack, flags = self.HEADER.unpack_from(data)
        # State transition
        match self._state:
            case self.STATE_ESTABLISHED:
                self._last_recd = now
                if flags & self.FLAG_FIN:
                    # Accept close request
                    print(f'{self.peer}: EST -> FIN/FIN_ACK -> FIN_ACK')
                    self._state = self.STATE_FIN_ACK
                    self._seq = (self._seq + 1) & 0xffffffff
                    self._ack = seq
                    self._ensure_fin_task = asyncio.create_task(self._ensure_fin())
                elif flags & self.FLAG_SYN:
                    if seq == self._ack:
                        # Resend dropped ACK
                        print(f'{self.peer}: EST -> SYN|SYN_ACK/ACK -> EST')
                        self._send(self._seq, self._ack, self.FLAG_ACK)
                        self._last_sent = now
                    else:
                        # Corrupted, duplicate SYN
                        print(f'{self.peer}: closed, corrupted SYN')
                        self.close()
                else:
                    # Normal operation
                    nsack = (flags >> 3) & 0xf
                    if nsack > self.MAX_SACK:
                        print(f'{self.peer}: closed for too many SACKs')
                        self.close()
                        return
                    if len(data) < self.HEADER.size + 8 * nsack:
                        print(f'{self.peer}: closed, SACKs not in header')
                        self.close()
                        return
                    if nsack:
                        sacks = struct.unpack_from(
                            '<' + 'II' * nsack, data, self.HEADER.size
                        )
                    else:
                        sacks = ()
                    payload = data[self.HEADER.size + 8 * nsack:]
                    if (
                        payload
                        and (seq - self._ack) & 0xffffffff < self.MAX_RECV_WINDOW
                        and self._reader_len + len(payload) <= self.MAX_READER_SIZE
                        and seq not in self._recd
                    ):
                        # EST -> data/ACK -> EST
                        self._process_seq(seq, payload)
                    if self._sent and flags & self.FLAG_ACK:
                        # EST -> ACK/- -> EST
                        self._process_ack(ack, sacks, now)
            case self.STATE_NEW:
                if flags & self.FLAG_FIN:
                    print(f'{self.peer}: NEW -> FIN/close -> CLS')
                    self.close()
                elif flags & self.FLAG_SYN:
                    if len(data) >= self.HEADER.size + 2:
                        self._swnd = struct.unpack_from('<H', data, self.HEADER.size)[0]
                    if not self._swnd:
                        print(f'{self.peer}: Closing, invalid WINDOW parameter')
                        self.close()
                        return
                    # Accept connection request
                    print(f'{self.peer}: NEW -> SYN/SYN_ACK -> SYN_ACK')
                    self._state = self.STATE_SYN_ACK
                    self._last_recd = now
                    self._ack = seq
                    self._ensure_syn_task = asyncio.create_task(self._ensure_syn())
                else:
                    print(f'{self.peer}: NEW -> ~SYN/close -> CLS')
                    self.close()
            case self.STATE_SYN:
                if flags & self.FLAG_FIN:
                    # Accept close request
                    print(f'{self.peer}: SYN -> FIN/FIN_ACK -> FIN_ACK')
                    self._state = self.STATE_FIN_ACK
                    self._ack = seq
                    self._last_recd = now
                    self._ensure_syn_task.cancel()
                    self._ensure_fin_task = asyncio.create_task(self._ensure_fin())
                elif flags & self.FLAG_SYN:
                    if len(data) >= self.HEADER.size + 2:
                        self._swnd = struct.unpack_from('<H', data, self.HEADER.size)[0]
                    if not self._swnd:
                        print(f'{self.peer}: Closing, invalid WINDOW parameter')
                        self.close()
                        return
                    self._ack = seq
                    if flags & self.FLAG_ACK:
                        if ack == self._seq:
                            # Connection accepted by peer
                            print(f'{self.peer}: SYN -> SYN_ACK/ACK -> EST')
                            self._state = self.STATE_ESTABLISHED
                            self._last_recd = now
                            self._ack = seq
                            self._peer_ack = ack
                            self._update_srtt_rto(now - self._last_sent)
                            self._send(self._seq, self._ack, self.FLAG_ACK)
                            self._last_sent = now
                            self._last_ack_sent = self._ack
                            self._ensure_syn_task.cancel()
                    else:
                        # Simultaneous connect
                        print(f'{self.peer}: SYN -> SYN/SYN_ACK -> SYN_ACK')
                        self._state = self.STATE_SYN_ACK
                        self._last_recd = now
                        self._ack = seq
            case self.STATE_SYN_ACK:
                if flags & self.FLAG_FIN:
                    # Accept close request
                    print(f'{self.peer}: SYN_ACK -> FIN/FIN_ACK -> FIN_ACK')
                    self._state = self.STATE_FIN_ACK
                    self._ack = seq
                    self._last_recd = now
                    self._ensure_syn_task.cancel()
                    self._ensure_fin_task = asyncio.create_task(self._ensure_fin())
                elif flags & self.FLAG_SYN:
                    if flags & self.FLAG_ACK:
                        if seq == self._ack and ack == self._seq:
                            print(f'{self.peer}: SYN_ACK -> SYN_ACK/ACK -> EST')
                            self._state = self.STATE_ESTABLISHED
                            self._peer_ack = ack
                            self._last_recd = now
                            self._send(self._seq, self._ack, self.FLAG_ACK)
                            self._last_sent = now
                            self._last_ack_sent = self._ack
                            self._ensure_syn_task.cancel()
                    elif seq == self._ack:
                        print(f'{self.peer}: SYN_ACK -> SYN/SYN_ACK -> SYN_ACK')
                        self._last_recd = now
                elif flags & self.FLAG_ACK and ack == self._seq:
                    # Connection accepted by peer
                    print(f'{self.peer}: SYN_ACK -> ACK/- -> EST')
                    self._state = self.STATE_ESTABLISHED
                    self._last_recd = now
                    self._peer_ack = ack
                    self._ensure_syn_task.cancel()
            case self.STATE_FIN:
                if flags & self.FLAG_FIN:
                    self._ack = seq
                    if flags & self.FLAG_ACK and ack == self._seq:
                        # Close request accepted by peer
                        print(f'{self.peer}: FIN -> FIN_ACK/ACK -> CLS')
                        self._state = self.STATE_CLOSED
                        self._last_recd = now
                        self._ack = seq
                        self._peer_ack = ack
                        self._send(self._seq, self._ack, self.FLAG_ACK)
                        self._last_sent = now
                        self._last_ack_sent = self._ack
                        self._ensure_fin_task.cancel()
                    else:
                        # Simultaneous close
                        print(f'{self.peer}: FIN -> FIN/FIN_ACK -> FIN_ACK')
                        self._state = self.STATE_FIN_ACK
                        self._last_recd = now
                        self._ack = seq
                        self._send(self._seq, self._ack, self.FLAG_FIN | self.FLAG_ACK)
                        self._last_sent = now
                        self._last_ack_sent = self._ack
            case self.STATE_FIN_ACK:
                if flags & self.FLAG_FIN:
                    if flags & self.FLAG_ACK:
                        print(f'{self.peer}: FIN_ACK -> FIN_ACK/ACK -> CLS')
                        self._state = self.STATE_CLOSED
                        self._last_recd = now
                        self._ack = seq
                        self._peer_ack = ack
                        self._send(self._seq, self._ack, self.FLAG_ACK)
                        self._last_sent = now
                        self._last_ack_sent = self._ack
                        self._ensure_fin_task.cancel()
                    else:
                        print(f'{self.peer}: FIN_ACK -> FIN/FIN_ACK -> FIN_ACK')
                        self._last_recd = now
                        self._ack = seq
                        self._send(self._seq, self._ack, self.FLAG_FIN | self.FLAG_ACK)
                        self._last_sent = now
                        self._last_ack_sent = self._ack
                elif flags & self.FLAG_ACK:
                    if ack == self._seq:
                        # Close request accepted by peer
                        print(f'{self.peer}: FIN_ACK -> ACK/- -> CLS')
                        self._state = self.STATE_CLOSED
                        self._last_recd = now
                        self._peer_ack = ack
                        self._ensure_fin_task.cancel()

    def _update_srtt_rto(self, rtt: float):
        # Update smoothed round trip time and resend timeout
        if self._srtt is None:
            self._srtt = rtt
            self._rttvar = rtt / 2
        else:
            delta = rtt - self._srtt
            self._srtt += 0.125 * delta
            self._rttvar += 0.25 * (abs(delta) - self._rttvar)
        self._rto = self._srtt + max(0.01, 4 * self._rttvar)

    def _process_seq(self, seq: int, payload: bytes):
        self._recd[seq] = payload
        # print(f'r {self.peer} seq: {seq & 0xf}, data: {len(self._recd[seq])}')
        # Move consecutive data into self._reader
        while True:
            recd = self._recd.pop(self._ack, None)
            if recd is None:
                break
            self._reader.feed_data(recd)
            self._reader_len += len(recd)
            self._ack = (self._ack + 1) & 0xffffffff
        while self._sacks and seq_le(self._sacks[0][0], self._ack):
            self._sacks.popleft()
        if seq_lt(self._ack, seq):
            # Process out-of-order sequence
            if len(self._sacks) >= self.MAX_SACK:
                self._sacks.popleft()
            self._sacks.append((seq, seq))
            self._sacks = deque(sorted(self._sacks))
            merged = deque()
            for s, e in self._sacks:
                if not merged or seq_lt(merged[-1][1], (s - 1) & 0xffffffff):
                    merged.append((s, e))
                else:
                    if seq_lt(e, merged[-1][1]):
                        e = merged[-1][1]
                    merged[-1] = (merged[-1][0], e)
            self._sacks = merged
        # Ensure ACK is sent
        if self._ensure_ack_task is None or self._ensure_ack_task.done():
            self._ensure_ack_task = asyncio.create_task(self._ensure_ack())

    def _process_ack(self, ack: int, sacks: tuple[int, ...], now: float):
        if seq_lt(ack, self._peer_ack):
            return
        if seq_lt(self._seq, ack):
            print(f'{self.peer}: closed, ACK > self._seq')
            self.close()
            return
        for i in range(0, len(sacks), 2):
            s, e = sacks[i:i+2]
            if seq_lt(e, s) or seq_lt(self._seq, e):
                print(f'{self.peer}: closed, invalid SACK range')
                self.close()
                return
            if not seq_lt(ack, s):
                if seq_lt(ack, e):
                    ack = e
                continue
            while seq_le(s, e):
                # Clear delivered packets sent
                match self._sent.pop(s, None):
                    case attempts, ts, pkt:
                        self._update_srtt_rto(now - ts)
                        # Congestion control
                        if self._cwnd < self._ssthresh:
                            # Slow start
                            self._cwnd += 1
                        else:
                            # Congestion avoidance
                            self._cwnd += 1 / self._cwnd
                s = (s + 1) & 0xffffffff
        if ack == self._peer_ack:
            self._dup_ack_count += 1
            if self._dup_ack_count == 3:
                # Fast retransmit
                match self._sent.get(ack):
                    case retries, ts, pkt:
                        self._send_raw(pkt)
                        self._last_sent = now
                        # Enter fast recovery
                        self._ssthresh = max(self._cwnd // 2, 1)
                        self._cwnd = self._ssthresh + 3
        else:
            self._dup_ack_count = 0
            while seq_lt(self._peer_ack, ack):
                # Clear delivered packets sent
                match self._sent.pop(self._peer_ack, None):
                    case attempts, ts, pkt:
                        self._update_srtt_rto(now - ts)
                        # Congestion control
                        if self._cwnd < self._ssthresh:
                            # Slow start
                            self._cwnd += 1
                        else:
                            # Congestion avoidance
                            self._cwnd += 1 / self._cwnd
                self._peer_ack = (self._peer_ack + 1) & 0xffffffff
        if self._acked and not self._acked.done():
            # Notify _send_datagram that _sent has been reduced
            if (self._seq - self._peer_ack) & 0xffffffff < min(self._swnd, self._cwnd):
                self._acked.set_result(None)
        if not self._sent and self._sent_heap:
            self._sent_heap: list[tuple[float, int]] = []
        if self._peer_ack == self._wait_ack:
            if self._send_done and not self._send_done.done():
                self._send_done.set_result(None)

    async def recv(self) -> bytes | None:
        try:
            if self._reader is None:
                return
            mlen = await self._reader.readexactly(4)
            self._reader_len -= 4
            mlen = int.from_bytes(mlen, 'little')
            if mlen <= self.MAX_MSG_SIZE:
                msg = await self._reader.readexactly(mlen)
                self._reader_len -= mlen
                return msg
            else:
                print(f'{self.peer}: closed, mlen > MAX_MSG_SIZE')
                self.close()
        except asyncio.IncompleteReadError as e:
            self._reader = None

    async def send(self, data: bytes) -> bool:
        if self._state != self.STATE_ESTABLISHED:
            raise Exception('Cannot send.  Socket connection is not established.')
        if len(data) > self.MAX_MSG_SIZE:
            raise ValueError('Message is too large to send.')
        mlen = len(data).to_bytes(4, 'little')
        self._wait_ack = (self._seq + (len(data) + self.MAX_PAYLOAD - 1) // self.MAX_PAYLOAD) & 0xffffffff
        self._send_done = asyncio.Future()
        if len(data) <= self.MAX_PAYLOAD:
            succ = await self._send_datagram(mlen + data)
        else:
            succ = await self._send_datagram(mlen + data[:self.MAX_PAYLOAD])
            if succ:
                for i in range(self.MAX_PAYLOAD, len(data), self.MAX_PAYLOAD):
                    succ = await self._send_datagram(data[i:i+self.MAX_PAYLOAD])
                    if not succ:
                        break
        if succ:
            print(f'{self.peer}:  Awaiting {self._wait_ack & 0xff}')
            await self._send_done
            if self._peer_ack != self._wait_ack:
                succ = False
        self._wait_ack = None
        self._send_done = None
        return succ

    def _send(self, seq: int, ack: int, flags: int, data: bytes = b'') -> bytes:
        if flags & self.FLAG_SYN:
            data = self.MAX_RECV_WINDOW.to_bytes(2, 'little')
        if self._sacks and not flags & (self.FLAG_FIN | self.FLAG_SYN):
            flags |= len(self._sacks) << 3
            sacks = b''.join(struct.pack('<II', s, e) for s, e in self._sacks)
        else:
            sacks = b''
        hdr = self.HEADER.pack(seq, ack, flags)
        pkt = b''.join([hdr, sacks, data])
        self._send_raw(pkt)
        return pkt
    
    def _send_raw(self, data: Datagram):
        if platform != 'win32':
            self.transport.sendto(data, self.peer)
        else:
            # Use zero appended address for the sake of Win32
            self.transport.sendto(data, self._zaddr)

    async def _send_datagram(self, data: bytes, flags: int = FLAG_ACK) -> bool:
        while (self._seq - self._peer_ack) & 0xffffffff >= min(self._swnd, self._cwnd):
            self._acked = asyncio.Future()
            await self._acked
        self._acked = None
        if self._state == self.STATE_ESTABLISHED:
            pkt = self._send(self._seq, self._ack, flags, data)
            now = time.monotonic()
            self._last_sent = now
            self._last_ack_sent = self._ack
            self._sent[self._seq] = 1, now, pkt
            heapq.heappush(self._sent_heap, (now + self._rto, self._seq))
            self._seq = (self._seq + 1) & 0xffffffff
            if self._ensure_seq_task is None:
                self._ensure_seq_task = asyncio.create_task(self._ensure_seq())
            return True
        return False

    async def _ensure_syn(self):
        try:
            now = time.monotonic()
            timeout = now + self.TIMEOUT
            while now < timeout:
                match self._state:
                    case self.STATE_SYN:
                        ack, flags = 0, self.FLAG_SYN
                    case self.STATE_SYN_ACK:
                        ack, flags = self._ack, self.FLAG_SYN | self.FLAG_ACK
                        self._last_ack_sent = ack
                    case _:
                        break
                self._send(self._seq, ack, flags)
                self._last_sent = time.monotonic()
                await asyncio.sleep(self._rto)
                now = time.monotonic()
            if self._state != self.STATE_ESTABLISHED:
                print(f'{self.peer}: closed, _ensure_syn, state != EST')
                self.close()
        finally:
            if self._state == self.STATE_ESTABLISHED:
                if not self.connected.done():
                    self.connected.set_result(None)
                self._keepalive_task = asyncio.create_task(self._keepalive())
                if self.on_connect is not None:
                    try:
                        self.on_connect(self)
                    except Exception as e:
                        pass
    
    async def _ensure_seq(self):
        while self._sent_heap:
            now = time.monotonic()
            while self._sent_heap and self._sent_heap[0][0] <= now:
                seq = heapq.heappop(self._sent_heap)[1]
                match self._sent.pop(seq, None):
                    case attempts, ts, pkt:
                        if (seq - self._peer_ack) & 0xffffffff < min(self._swnd, self._cwnd):
                            # Resend packet
                            self._send_raw(pkt)
                            self._last_sent = now
                            self._sent[seq] = attempts + 1, now, pkt
                            rto = now + self._rto * self.BACKOFF_MULTIPLIER ** attempts
                            heapq.heappush(self._sent_heap, (rto, seq))
                        else:
                            # Update timestamps
                            self._sent[seq] = attempts, now, pkt
                            heapq.heappush(self._sent_heap, (now + self._rto, seq))
            if self._sent_heap:
                wait = max(0.01, self._sent_heap[0][0] - time.monotonic())
                await asyncio.sleep(wait)
        self._ensure_seq_task = None

    async def _ensure_ack(self):
        await asyncio.sleep(self.DELAYED_ACK_TO)
        if self._last_ack_sent != self._ack and self._state == self.STATE_ESTABLISHED:
            self._send(self._seq, self._ack, self.FLAG_ACK)
            self._last_sent = time.monotonic()
            self._last_ack_sent = self._ack
        self._ensure_ack_task = None

    async def _keepalive(self):
        while self._state == self.STATE_ESTABLISHED:
            now = time.monotonic()
            recv_wait = self._last_recd + self.TIMEOUT - now
            if recv_wait < 0:
                # Close Socket when peer doesn't send
                break
            ping_wait = self._last_sent + self.KEEPALIVE_TO - now
            if ping_wait < 0:
                self._send(self._seq, self._ack, self.FLAG_ACK)
                self._last_sent = now
                self._last_ack_sent = self._ack
            else:
                wait = min(recv_wait, ping_wait)
                await asyncio.sleep(wait)
        print(f'{self.peer}: closed, keepalive, state == {self._state}')
        self.close()
        self._keepalive_task = None

    async def _ensure_fin(self):
        try:
            now = time.monotonic()
            timeout = now + self.TIMEOUT
            while now < timeout:
                match self._state:
                    case self.STATE_FIN:
                        ack, flags = 0, self.FLAG_FIN
                    case self.STATE_FIN_ACK:
                        ack, flags = self._ack, self.FLAG_ACK | self.FLAG_FIN
                        self._last_ack_sent = ack
                    case _:
                        break
                self._send(self._seq, ack, flags)
                self._last_sent = time.monotonic()
                await asyncio.sleep(min(timeout - now, self._rto))
                now = time.monotonic()
        finally:
            if self._state != self.STATE_CLOSED:
                self._state = self.STATE_CLOSED
            if not self.closed.done():
                self.closed.set_result(None)
            if self._acked and not self._acked.done():
                self._acked.set_result(None)
            if self._send_done and not self._send_done.done():
                self._send_done.set_result(None)
            self._sent = {}
            self._sent_heap = []
            self._recd = {}
            self._reader.feed_eof()
            if self._ensure_syn_task and not self._ensure_syn_task.done():
                self._ensure_syn_task.cancel()
            if self._ensure_seq_task and not self._ensure_seq_task.done():
                self._ensure_seq_task.cancel()
            if self._ensure_ack_task and not self._ensure_ack_task.done():
                self._ensure_ack_task.cancel()
            if self._keepalive_task and not self._keepalive_task.done():
                self._keepalive_task.cancel()
            if self.on_close is not None:
                try:
                    self.on_close(self)
                except Exception as e:
                    pass


class Peer(object):

    def __init__(self,
        addr: Address, sock: Socket, msg_q: MessageQueue,
        handler: asyncio.Task | None = None,
        recvr: asyncio.Task | None = None
    ):
        self.addr = addr
        self.sock = sock
        self.msg_q = msg_q
        self.handler = handler
        self.recvr = recvr
        self.peers_sub: bool = False


### MeshProtocol

class MeshProtocol(asyncio.DatagramProtocol):
    '''Protocol to handle UDP datagrams for the Mesh class.'''
    def __init__(self, mesh: Mesh):
        self.mesh = mesh

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport

    def datagram_received(self, data: Datagram, addr: Address):
        # Route Datagram to mesh.peers[addr]
        addr = addr[:2]
        peer = self.mesh.peers.get(addr) or self.mesh.accept(addr)
        if peer:
            peer.sock.datagram_received(data)

    def error_received(self, exc: OSError):
       print(f'Error receieved: {exc}')


### Mesh

class Mesh(object):

    BLACKLIST_TIMEOUT = 600.0

    def __init__(self,
            addr: Address,
            broker: broker.Broker,
            bootstrap: list[Address] = [],
            loop: asyncio.AbstractEventLoop | None = None,
            max_peers: int | None = None
    ):
        self.addr = addr
        self.broker = broker
        self.bootstrap = bootstrap
        self.loop = loop or asyncio.get_running_loop()
        self.max_peers = max_peers
        self.peers: dict[Address, Peer] = {}
        self.neighbors: dict[Address, set[Address]] = {}
        self.blacklist: dict[Address, float] = {}
        self.transport: asyncio.DatagramTransport | None = None
        self.protocol: MeshProtocol | None = None
        self.running: bool = False
        self.handler: asyncio.Task | None = None
        self.expander: asyncio.Task | None = None

    async def start(self):
        if self.running:
            return
        self.running = True
        self.transport, self.protocol = await self.loop.create_datagram_endpoint(
            lambda: MeshProtocol(self),
            local_addr=self.addr,
            family=socket.AF_INET6
        )
        self.handler = self.loop.create_task(self.handle_broker())
        for addr in self.bootstrap:
            self.connect(addr)
        self.expander = self.loop.create_task(self.expand_network())

    async def stop(self):
        if not self.running:
            return
        self.running = False
        if self.handler and not self.handler.done():
            self.handler.cancel()
        if self.expander and not self.expander.done():
            self.expander.cancel()
        for peer in self.peers.values():
            if peer.handler and not peer.handler.done():
                peer.handler.cancel()
        futures = [p.sock.close() for p in self.peers.values()]
        futures = [f for f in futures if not f.done()]
        try:
            await asyncio.wait_for(asyncio.gather(*futures), 5)
        except asyncio.TimeoutError as e:
            pass
        self.blacklist.clear()
        self.peers.clear()
        self.neighbors.clear()
        self.transport.close()
        self.transport = None
        self.protocol = None

    def accept(self, addr: Address) -> Peer | None:
        if addr in self.peers:
            # Already connected to peer
            return
        # Check blacklist
        timeout = self.blacklist.get(addr, 0)
        if timeout:
            if time.monotonic() < timeout:
                # Drop requests from blacklisted peers
                return
            del self.blacklist[addr]
        # Create connection
        sock = Socket(
            peer=addr,
            transport=self.transport,
            on_connect=self.handle_connect,
            on_close=self.handle_close
        )
        peer = Peer(addr, sock, asyncio.Queue())
        # Add peer to self.peers
        self.peers[addr] = peer
        return peer

    def connect(self, addr: Address):
        peer = self.accept(addr)
        if peer:
            peer.sock.connect()

    def handle_connect(self, sock: Socket):
        peer = self.peers.get(sock.peer, None)
        if not peer:
            return
        peer.handler = self.loop.create_task(self.handle_peer(peer))

    def handle_close(self, sock: Socket, blacklist: bool = True):
        peer = self.peers.pop(sock.peer, None)
        if not peer:
            return
        if peer.handler:
            if not peer.handler.done():
                peer.handler.cancel()
        if blacklist:
            print(f'Blacklisted {peer.addr}')
            self.blacklist[peer.addr] = time.monotonic() + self.BLACKLIST_TIMEOUT

    async def handle_peer(self, peer: Peer):
        try:
            await self.broker.pub(broker.PeerConnected(peer.addr))
            # Set up connection
            await peer.sock.send(msg_peers_sub(active=True))
            # Process peer.msg_q
            peer.recvr = self.loop.create_task(self.handle_recv(peer))
            while not peer.recvr.done() and peer.sock.state == peer.sock.STATE_ESTABLISHED:
                match await peer.msg_q.get():
                    case None:
                        break
                    case MsgToSend() as msg:
                        await peer.sock.send(msg.msg)
                    case MsgPeersSub() as msg:
                        if msg.active and not peer.peers_sub:
                            peer.peers_sub = True
                            # Send peers addresses to peer
                            peers = {
                                a for a, p in self.peers.items()
                                if p.handler and not p.handler.done() and a != peer.addr
                            }
                            # Drop or send multiple msg_peers_pub(added=set(peers))
                            smsg = set(list(peers)[:0x7fff]) if len(peers) >> 15 else peers
                            smsg = msg_peers_pub(added=smsg)
                            peers = None
                            await peer.sock.send(smsg)
                            smsg = None
                        elif peer.peers_sub and not msg.active:
                            peer.peers_sub = False
                    case MsgPeersPub() as msg:
                        if not peer.peers_sub:
                            # Silently drop peer publications
                            continue
                        nbrs = self.neighbors.get(peer.addr, set())
                        nbrs.update(added for added in msg.added if added not in self.peers)
                        nbrs.difference_update(msg.removed)
                        self.neighbors[peer.addr] = nbrs
                        nbrs = None
                    case MsgPeersReq() as msg:
                        nbr = self.peers.get(msg.neighbor)
                        if nbr is None:
                            # Ignore missing peers
                            continue
                        if nbr.sock.state != nbr.sock.STATE_ESTABLISHED:
                            # Don't pair with unconnected peers
                            continue
                        # Exchange responses
                        await nbr.msg_q.put(MsgToSend(msg_peers_res(peer.addr)))
                        await peer.sock.send(msg_peers_res(msg.neighbor))
                        nbr = None
                    case MsgPeersRes() as msg:
                        if self.max_peers and len(self.peers) >= self.max_peers:
                            # Don't exceed limit of self.max_peers
                            continue
                        self.connect(msg.neighbor)
        except Exception as e:
            import traceback
            print(f'{self.addr}, {peer.addr}: Exception: {e}')
            traceback.print_exc()
            raise
        finally:
            await self.broker.pub(broker.PeerDisconnected(peer.addr))
            if peer.recvr and not peer.recvr.done():
                peer.recvr.cancel()

    async def handle_recv(self, peer: Peer):
        while True:
            msg = await peer.sock.recv()
            try:
                msg = DESERIALIZE[msg[:1]](msg)
            except Exception as e:
                await peer.msg_q.put(None)
                break
            await peer.msg_q.put(msg)

    async def handle_broker(self):
        subs = {broker.PeerConnected, broker.PeerDisconnected}
        try:
            event_q: EventQueue = asyncio.Queue()
            for sub in subs:
                self.broker.sub(sub, event_q)
            while self.running:
                event = await event_q.get()
                match event:
                    case broker.PeerConnected():
                        msg = MsgToSend(msg_peers_pub(added={event.addr}))
                        for addr, peer in self.peers.items():
                            if peer.peers_sub and addr != event.addr:
                                await peer.msg_q.put(msg)
                        msg = None
                    case broker.PeerDisconnected():
                        msg = MsgToSend(msg_peers_pub(removed={event.addr}))
                        for addr, peer in self.peers.items():
                            if peer.peers_sub:
                                await peer.msg_q.put(msg)
                        msg = None
        finally:
            for sub in subs:
                self.broker.unsub(sub, event_q)

    async def expand_network(self):
        while self.running:
            # Sleep when at max peers
            if self.max_peers and len(self.peers) >= self.max_peers:
                await asyncio.sleep(1)
                continue
            # Find neighbor connected to peer
            peer = None
            neighbor = None
            while self.neighbors:
                peer = random.choice(list(self.neighbors.keys()))
                if peer not in self.peers:
                    del self.neighbors[peer]
                    continue
                neighbors = self.neighbors[peer]
                if not neighbors:
                    del self.neighbors[peer]
                    continue
                neighbor = random.choice(list(neighbors))
                if neighbor in self.peers:
                    neighbors.discard(neighbor)
                    neighbor = None
                    if not neighbors:
                        del self.neighbors[peer]
                    continue
                else:
                    break
            if peer is None or neighbor is None:
                await asyncio.sleep(1)
                continue
            peer = self.peers.get(peer)
            if peer is None:
                await asyncio.sleep(1)
                continue
            # Send request to meet neighbor to peer
            msg = MsgToSend(msg_peers_req(neighbor=neighbor))
            await peer.msg_q.put(msg)
            await asyncio.sleep(1)
