
from asyncio import get_running_loop, create_task, wait, sleep, Queue, Task, FIRST_COMPLETED
from time import time
from secrets import token_bytes
from ipaddress import ip_address, IPv4Address
from bisect import bisect_left
from random import choice
from functools import cache
from socket import socket, AF_INET, SOCK_DGRAM
from select import select
from datetime import datetime
from struct import pack, unpack

from .crypto import keccak_800, keccak_1600 as _keccak_1600, sign, verify, keypair, key_exchange, encrypt, decrypt


def keccak_1600(msg: bytes, outlen: int = 32) -> bytes:
    return _keccak_1600(msg, outlen)


class Fragment(object):

    def __init__(self, value: bytes, msg_hash: bytes, offset: int, nfrags: int):
        self.value = value
        self.msg_hash = msg_hash
        self.offset = offset
        self.nfrags = nfrags


class Message(object):

    def __init__(self, value: bytes | None = None, fragments: list[Fragment] = []):
        self._value = value
        self._digest = keccak_1600(value, 16) if value else None
        self._fragments = fragments
        self._offsets = {frag.offset for frag in fragments}

    @property
    def complete(self) -> bool:
        if self._value:
            return True
        if not self._fragments:
            return False
        if len(self._offsets) < max(frag.nfrags for frag in self._fragments):
            return False

    @property
    def valid(self) -> bool | None:
        if self._value:
            return True
        if not self._fragments:
            return True
        nfrags = self._fragments[0].nfrags
        if any(frag.nfrags != nfrags for frag in self._fragments):
            return False
        msg_hash = self._fragments[0].msg_hash
        if any(frag.msg_hash != msg_hash for frag in self._fragments):
            return False
        if min(self._offsets) < 0 or max(self._offsets) >= nfrags:
            return False
        return True

    @property
    def value(self) -> bytes | None:
        if self._value:
            return self._value
        if not self.complete or not self.valid:
            return
        fragments = sorted(
            ((frag.offset, frag.value) for frag in self._fragments),
            key=(lambda k: k[0])
        )
        value = b''.join(frag for _, frag in fragments)
        msg_hash = keccak_1600(value, 16)
        if msg_hash == self._fragments[0].msg_hash:
            self._value = value
            self._digest = msg_hash

    @property
    def digest(self) -> bytes | None:
        if not self._digest:
            if not self.value:
                return
        return self._digest

    @property
    def fragments(self) -> list[Fragment] | None:
        FRAGMENT_SIZE = 512
        if self._fragments:
            return self._fragments
        if not self.value:
            return
        msg_hash = self._digest
        nfrags = (len(self._value) + FRAGMENT_SIZE - 1) // FRAGMENT_SIZE
        self._fragments = [
            Fragment(
                value=self._value[offset*FRAGMENT_SIZE:(offset+1)*FRAGMENT_SIZE],
                msg_hash=msg_hash,
                offset=offset,
                nfrags=nfrags
            )
            for offset in range(nfrags)
        ]
        return self._fragments

    def add_fragment(self, fragment: Fragment):
        if self.value:
            return
        self._fragments.append(fragment)
        self._offsets.add(fragment.offset)


class MessageSet(object):

    def __init__(self, msgs: bytes | list[bytes]):
        self._imsgs = None if isinstance(msgs, bytes) or not msgs else iter(msgs)
        self._imsg: bytes = msgs if isinstance(msgs, bytes) else next(self._imsgs)
        self._iter: int = 0

    def __iter__(self):
        return self

    def __next__(self) -> bytes:
        while True:
            msgs_len: int = unpack('<H', self._imsg[:2])[0] if self._imsg else 0
            if self._iter <= msgs_len:
                offset = 2 + 2*self._iter
                if self._iter == msgs_len - 1:
                    offset = unpack('<H', self._imsg[offset:offset+2])[0]
                    next_offset = len(self._imsg)
                else:
                    offset, next_offset = unpack('<HH', self._imsg[offset:offset+4])
                return self._imsg[offset:next_offset]            
            if self._imsgs is None:
                raise StopIteration
            self._imsg = next(self._imsgs)
            self._iter = 0
    
    async def _sendto(self, msg: bytes, peer: "Peer"):
        loop = get_running_loop()
        await loop.sock_sendto(peer.sock, msg, peer.addr)

    def sendto(self, peer: "Peer") -> list[Task]:
        new_msgs: list[bytes] = []
        new_msg: list[bytes] = []
        msg_len: int = 2
        for msg in self:
            if not msg:
                continue
            if len(msg) > peer.MTU_1300 + 4:
                raise Exception(f"Unable to send large message of size {len(msg)}")
            if msg_len + 2 + len(msg) > peer.MTU_1300:
                new_msg.insert(0,
                    pack('<H' + 'H'*len(new_msg), len(new_msg), *[
                        len(m) for m in new_msg
                    ])
                )
                new_msgs.append(b''.join(new_msg))
                new_msg, msg_len = [], 2
            new_msg.append(msg)
            msg_len += 2 + len(msg)
        if new_msg:
            new_msg.insert(0,
                pack('<H' + 'H'*len(new_msg), len(new_msg), *[
                    len(m) for m in new_msg
                ])
            )
            new_msgs.append(b''.join(new_msg))
        return [
            create_task(self._sendto(msg, peer)) for msg in new_msgs
        ]


class Peer(object):

    MTU_1300 = 1300

    def __init__(self,
        key: bytes,
        secret: bytes,
        addr: tuple[str, int],
        sock: socket
    ):
        self.key = key
        self.secret = secret
        self.addr = addr
        self.sock = sock
        self.id: int = sum(
            b << (8*i) for i, b in enumerate(keccak_800(key[:32]))
        )
        self.recv_q = Queue()
        self.nonce: int = 0
        self.last_recvd = time()

    async def send_msg(self, msg: bytes):
        self.sock.sendto(msg, self.addr)

    @property
    def tasks(self) -> list[Task]:
        return [
            self.process_recv_q()
        ]

    async def process_recv_q(self):
        while not self.recv_q.empty():
            item = await self.recv_q.get()
            if isinstance((item := await self.recv_q.get()), Frames):
                pass

    def send_ping(self):
        msg = b''.join([
            self.key, token_bytes(16),
            pack('<QQ', int(time()*1_000_000), self.nonce)
        ])
        self.nonce += 1
        self.sock.sendto(msg, self.addr)
    
    def send_fragments(self, frags: list[bytes]):
        while frags:
            msg_len, msg = 2, []
            for frag in frags:
                if ((frag_len := len(frag)) + msg_len) > MTU_1300:
                    break
                msg += [pack("<H", frag_len), frag]
                msg_len += 2 + frag_len
            msg_len = len(msg) // 2
            frags = frags[msg_len:]
            msg = b''.join([
                self.key, token_bytes(16),
                pack('<QQH', int(time()*1_000_000), self.nonce, msg_len)
            ] + msg)
            self.nonce += 1
            self.sock.sendto(encrypt(self.secret, msg), self.addr)

    async def recv_msg(self, msg: bytes):
        self.last_recvd = time()
        if len(msg) >= 96:
            await self.q.put(Fragments(decrypt(self.secret, msg)))


class Chord(object):

    def __init__(self, keypair: bytes, sock: socket):
        self.secret = keypair[:32]
        self.key = keypair[32:]
        self.id: int = sum(
            b << (8*i) for i, b in enumerate(keccak_800(self.key[:32]))
        )
        self.sock = sock
        self.tasks: set[Task] = set()
        self.key_to_peer: dict[bytes, Peer] = {}
        self.peer_ids: list[int] = []
        self.fingers = [
            (self.id + (2 ** (16*i))) % (2 ** 256) for i in range(16)
        ]
        self.finger_to_peer: dict[int, Peer] = {}
        self.q = Queue()

    async def main(self) -> "Chord":
        await wait(self.tasks)

    
    async def recv_msg(self, msg: bytes, addr: tuple[str, int]):
        if (key := msg[32:64]) not in self.key_to_peer:
            self.add_peer(key, addr)
        await self.key_to_peer[key].recv_msg(msg)

    def add_peer(self, key: bytes, addr: tuple[str, int]):
        secret = key_exchange(self.secret, key)
        peer = Peer(key + self.key, secret, addr, self.sock)
        self.key_to_peer[key] = peer
        self.peers.add(create_task(peer.main()))


class Network(object):

    def __init__(self, port: int = 4700):
        self.sock = socket(AF_INET, SOCK_DGRAM)
        self.sock.bind(("", port))
        self.key_to_chord: dict[bytes, Chord] = {}
        self.chord_to_key: dict[Chord, bytes] = {}
        self.tasks: set[Task] = set()
        self.task_to_chord: dict[Task, Chord] = {}

    async def recv_msg(self):
        select_args = (self.sock,), (), (), 0
        while True:
            while select(*select_args)[0]:
                msg, addr = self.sock.recvfrom(4096)
                if len(msg) < 96:
                    continue
                if (key := msg[:32]) in self.key_to_chord:
                    await self.key_to_chord[key].recv_msg(msg, addr)
            sleep(.1)
    
    async def main(self):
        recv = create_task(self.recv_msg())
        self.tasks

    def add_chord(self, keypair: bytes):
        chord = Chord(keypair=keypair, sock=self.sock)
        key = keypair[32:64]
        self.key_to_chord[key] = chord
        self.chord_to_key[chord] = key
        task = create_task(chord.main())
        self.tasks.add(task)
        self.task_to_chord[task] = chord
        task.add_done_callback(self.remove_chord)

    def remove_chord(self, task: Task):
        self.tasks.remove(task)
        chord = self.task_to_chord.pop(task)

