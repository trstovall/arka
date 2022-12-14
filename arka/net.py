
from secrets import token_bytes
from asyncio import DatagramProtocol, DatagramTransport
from ipaddress import ip_address, IPv4Address
from bisect import bisect_left
from random import choice
from functools import cache
from socket import socket, AF_INET, SOCK_DGRAM
from select import select
from datetime import datetime

from .crypto import keccak_800, keccak_1600, ed25519_sign, ed25519_verify, keypair, key_exchange
from .msgpack import pack, unpack, Error as SerdesError


HashDigest = bytes

class Error(Exception):
    '''network error'''


class Ext(object):

    typecode: int
    fields: tuple[str]

    @cache
    @property
    def __msgpack__(self) -> tuple[int, bytes]:
        return self._typecode, pack(tuple(
            getattr(self, field)
            for field in self.fields
        ))

    @cache
    @classmethod
    def unpack(cls, data) -> "Ext":
        return cls(**dict(zip(cls.fields, unpack(data))))


class Identifier(object):

    typecode = 1

    def __init__(self, id: int, len: int = 32):
        super().__init__()
        self.id = id
        self.len = len

    @cache
    @property
    def __msgpack__(self) -> tuple[int, bytes]:
        return self.typecode, self.key

    @cache
    @classmethod
    def unpack(cls, data) -> object:
        return cls(
            id=sum(x << (8*i) for i, x in enumerate(data)),
            len=len(data)
        )

    @cache
    @property
    def key(self) -> bytes:
        return bytes(
            (id >> 8*i) & 0xff for i in range(self.len)
        )

    @cache
    def __lt__(self, other: "Identifier") -> bool:
        return self.id < other.id
    @cache
    def __le__(self, other: "Identifier") -> bool:
        return self.id <= other.id
    @cache
    def __eq__(self, other: "Identifier") -> bool:
        return self.id == other.id
    @cache
    def __ne__(self, other: "Identifier") -> bool:
        return self.id != other.id
    @cache
    def __ge__(self, other: "Identifier") -> bool:
        return self.id >= other.id
    @cache
    def __gt__(self, other: "Identifier") -> bool:
        return self.id > other.id


class Secret(Identifier):

    typecode = 2

    def __init__(self, seed: bytes | None = None):
        self.seed: bytes = seed or token_bytes(32)
        self.keypair = keypair(seed)
        super().__init__(id=Identifier.unpack(self.key).id)

    @cache
    @property
    def __msgpack__(self) -> tuple[int, bytes]:
        return self.typecode, self.seed

    @cache
    @classmethod
    def unpack(cls, data) -> object:
        return cls(seed=data)

    @cache
    @property
    def key(self) -> bytes:
        return self.keypair[32:]

    @cache
    @property
    def id(self) -> Identifier:
        return Identifier(
            id=sum(x << (8*i) for i, x in enumerate(self.key)),
            len=len(self.key)
        )

    @cache
    def sign(self, nonce: HashDigest) -> "Signature":
        x, m = self.seed, nonce
        return Signature(id=self.id, nonce=nonce, sr=ed25519_sign(x, m)))

    def key_exchange(self, other: Identifier, nonce: HashDigest) -> "Secret":
        x, A = self.seed, other.key
        keypair = key_exchange(x, A, nonce)
        return self.__class__(seed=keypair[:32])


class Signature(Identifier):

    typecode = 3

    def __init__(self, id: Identifier = None, nonce: HashDigest = None, sr: bytes = None):
        super().__init__(id=id.id, len=id.len)
        self.nonce = nonce
        self.sr = sr

    @cache
    def verify(self) -> bool:
        A, m, sr = self.key, self.nonce, self.sr
        return bool(ed25519_verify(sr, A, m))


class Node(Identifier):

    typecode = 3

    def __init__(self, id: Identifier, data: bytes | None = None) -> None:
        super().__init__(id=id.id)

    @property
    def __msgpack__(self) -> tuple[int, bytes]:
        return self.typecode, pack((self._id, self.data))

    @classmethod
    def unpack(cls, data) -> "Node":
        return cls(*unpack(data))

    @property
    def id(self) -> int:
        return self._id.id

    def __lt__(self, other: "Node") -> bool:
        return self.id < other.id
    
    def __le__(self, other: "Node") -> bool:
        return self.id <= other.id
    
    def __eq__(self, other: "Node") -> bool:
        return self.id == other.id
    
    def __ne__(self, other: "Node") -> bool:
        return self.id != other.id
    
    def __ge__(self, other: "Node") -> bool:
        return self.id >= other.id
    
    def __gt__(self, other: "Node") -> bool:
        return self.id > other.id


class Peer(Node):

    def __init__(self, network: "Network", id=None, secret=None):
        super().__init__(id=None, data={})
        self.network = network
        self.secret: Secret = None
        self.bit: int = None
        self._sent: list[HashDigest] = []
        self._recv: list[HashDigest] = []
        self.out_queue = []
    
    def recv(self, data: bytes) -> None:
        data = memoryview(data)
        _hash, _data = data[:32], data[32:]
        if _hash != hash(_data).digest():
            raise Error("Invalid packet hash")
        self._recv.append(_hash)
        packet: Packet = unpack(_data, handlers={Packet.typecode: Packet.unpack})
        if self.id is None:
            if packet.to != self.network.secret.identifier:
                raise Error("Received packet with unknown address.")
            if packet.sender is None:
                raise Error("Received packet with no sender.")
            self.id: Identifier = packet.sender
            self.secret = self.network.secret.key_exchange(
                self.id, packet.timestamp, packet.nonce
            )
            self.bit = int(self.id < self.network.secret.identifier)



    def send(self, data: bytes) -> None:
        pass

    @property
    def alive(self) -> bool:
        raise NotImplementedError

    def get(self, id: Identifier) -> bytes | None:
        raise NotImplementedError

    def set(self, id: Identifier, data: bytes = None) -> None:
        raise NotImplementedError
    
    def find(self, id: Identifier) -> "Peer":
        raise NotImplementedError
    
    def pair(self, host: "Host", peer: "Peer"):
        pass


class Registry(Peer):
    """Peer with static IP"""


class Network(DatagramProtocol):

    def __init__(self, secret: Secret, registries: list[Registry]):
        self.host = Peer(self, id=id, None, None)
        self.secret = secret
        self.registries = registries
        self.conn: dict[tuple[str, int], Connection] = {}
        self.peers: list[Peer] = [self.host]
        self.fingers: set[Peer] = set()
        self.subnets: list[Subnet] = []
        for registry in registries:
            self.connect(registry.find(self.host.id), registry)

    def connection_made(self, transport: DatagramTransport) -> None:
        self.tx = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            if (conn := self.conn.get(addr)) is None:
                conn = Connection(self.secret)
            conn.recv(data)
        except Exception as e:
            pass

    def send(self, to: Peer, msg: bytes) -> None:
        pass

    def connect(self, peer: Peer, registry: Registry | None = None) -> bool:
        if peer.addr not in self.conn:
            self.conn[peer.addr] = Connection(self.host, peer, registry)

    def add_peer(self, peer: Peer) -> bool:
        i = bisect_left(self.peers, peer)
        if self.peers[i % len(self.peers)] == peer:
            return False
        self.peers.insert(i, peer)
        return True

    def disconnect(self, peer: Peer) -> None:
        conn = self.conn.pop(peer.addr, None)
        if conn is not None:
            conn.close()

    def remove_peer(self, peer: Peer) -> bool:
        i = bisect_left(self.peers, peer) % len(self.peers)
        if self.peers[i] != peer:
            return False
        self.peers.pop(i)
        return True

    def find(self, id: Identifier) -> Peer:
        i = bisect_left(self.peers, Node(id=id))
        if (succ := self.peers[i % len(self.peers)]) is self:
            return self
        if (pred := self.peers[i - 1]) is self:
            return succ.find(id)
        return pred.find(id)

    def stabilize(self) -> None:
        fingers = {
            self.find(id) for id in (
                Identifier((self.id + 2 ** i) % (2 ** 256))
                for i in range(0, 256, 8)
            )
        } - {self}
        old, new = self.fingers, fingers
        for peer in old - new:
            self.disconnect(peer)
            peer.disconnect(self)
        for peer in new - old:
            self.connect(peer)
            peer.connect(self)
        self.fingers = fingers
        self.peers = [peer for peer in self.peers if peer.alive]


class Subnet(object):

    def __init__(self, clique: list[Peer], pred: list[Peer], succ: list[Peer]):
        pass


class Message(object):

    typecode: int = 0x00

    @classmethod
    def unpack(cls, data):
        _hash, _data = unpack(data)
        if _hash != hash(_data).digest():
            raise Error("Bad Message")
        return cls(_data)

    def __init__(self, data: bytes):
        if len(data) == 0:
            raise Error("No data in Message")
        if len(data) > 2 ** 15:
            raise Error("Message too big")
        self.data = data
    
    @property
    def hash(self) -> HashDigest:
        if not hasattr(self, "_hash"):
            self._hash = hash(self.data).digest()
        return self._hash

    @property
    def parts(self) -> list[bytes]:
        if not hasattr(self, "_parts"):
            self._parts = [self.data[i:(i + 1) * 1024] for i in range(0, len(self.data), 1024)]
            part = self._parts[-1]
            rem = len(part) % 64
            if rem:
                self._parts[-1] = part + (64 - rem) * b'\x00'
        return self._parts
    
    @property
    def fragments(self) -> list["Fragment"]:
        if not hasattr(self, "_frag"):
            hash = self.hash
            nparts = len(self.parts)
            self._frag = [Fragment(hash, nparts, i, part) for i, part in enumerate(self.parts)]
        return self._frag


class Fragment(object):

    typecode: int = 0x01

    @property
    def __msgpack__(self) -> tuple[int, bytes]:
        if not hasattr(self, "_packed"):
            self._packed = pack((self.msg, self.nparts, self.part, self.data))
        return self.typecode, self._packed

    @classmethod
    def unpack(cls, data):
        _hash, _packed = unpack(data)
        if _hash != hash(_packed).digest():
            raise Error("Bad Fragment")
        return cls(*unpack(_packed))

    def __init__(self, msg: HashDigest, nparts: int, part: int, data: bytes):
        self.msg, self.nparts, self.part, self.data = msg, nparts, part, data
    
    @property
    def hash(self) -> bytes:
        if not hasattr(self, "_hash"):
            self._hash = hash(pack(self)).digest()
        return self._hash


class Packet(Ext):

    version = -1
    typecode = 0
    fields = (
        "version",
        "sent",
        "recv",
        "to",
        "sender",
        "timestamp",
        "nonce",
        "data",
    )

    def __init__(self,
        version: int,
        sent: HashDigest,
        recv: HashDigest | None,
        to: Identifier,
        sender: Identifier | None,
        timestamp: datetime,
        nonce: bytes,
        data: list[Message | Fragment],
    ):
        if version != self.version:
            raise Error("Invalid packet version")
        self.sent, self.recv, self.to, self.sender, self.timestamp, self.nonce, self.data = (
            sent, recv, to, sender, timestamp, nonce, data
        )
