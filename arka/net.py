
from time import time
from bisect import bisect_left
from random import choice
from socket import socket, create_connection
from select import select
from datetime import datetime
from struct import unpack_from, pack_into
from arka.messages import ArkaProtocolInitMessage
from typing import Generator
from enum import IntEnum, auto
from os import urandom

import queue as q


class MessageEnum(IntEnum):
    #
    INIT = 0
    #
    CHALLENGE_ANSWER = 1
    #
    SERVER_STREAM_ITEM = auto()
    #
    TX_HASH_STREAM_ITEM = auto()
    #
    TX_ITEM_REQUEST = auto()
    TX_ITEM_RESPONSE = auto()
    #
    BLOCK_HEADER_REQUEST = auto()
    BLOCK_HEADER_RESPONSE = auto()
    #
    BLOCK_HEADER_STREAM_ITEM = auto()
    #
    BLOCK_CONTENTS_REQUEST = auto()
    BLOCK_CONTENTS_RESPONSE = auto()
    #
    BLOCK_REQUEST = auto()
    BLOCK_RESPONSE = auto()


class Message(object):

    MAX_MESSAGE_SIZE = 2 ** 23

    def __init__(self, size: int):
        if 0 < size <= self.MAX_MESSAGE_SIZE:
            self.buff = bytearray(size)
            self.view = memoryview(self.buff)
        else:
            raise ValueError('message size is invalid.')


class InitMessageBuilder(object):

    BANNER = b'arka'

    def __init__(self, key: bytes, challenge: bytes):
        self.key = key
        self.challenge = challenge
    
    def build(self) -> Message:
        msg = Message(69)
        msg.view[0] = MessageEnum.INIT.value    # message id: 1 byte
        msg.view[1:5] = self.BANNER             # arka banner: 4 bytes
        msg.view[5:37] = self.key               # local node key: 32 bytes
        msg.view[37:69] = self.challenge        # challenge for remote node: 32 bytes
        return msg


class InitMessageView(object):

    def __init__(self, msg: Message):
        if len(msg.buff) != 69:
            raise ValueError("msg argument for InitMessageView must be 69 bytes long.")
        if msg.view[1:5] != b'arka':
            raise ValueError("arka banner not set for msg argument to InitMessageView.")
        self.buff = msg.buff
        self.view = msg.view
    
    @property
    def key(self) -> bytes:
        return bytes(self.view[5:37])
    
    @property
    def challenge(self) -> bytes:
        return bytes(self.view[37:69])


class ChallengeAnswerMessageBuilder(object):

    def __init__(self, answer: bytes):
        self.answer = answer

    def build(self) -> Message:
        msg = Message(65)
        msg.view[0] = MessageEnum.CHALLENGE_ANSWER.value    # message topic: 1 byte
        msg.view[1:] = self.answer                          # signature of challenge: 64 bytes
        return msg


class ChallengeAnswerView(object):

    def __init__(self, msg: Message):
        if len(msg.buff) != 65:
            raise ValueError("msg argument for ChallengeAnswerView must be 65 bytes long.")
        self.buff = msg.buff
        self.view = msg.view
    
    @property
    def answer(self) -> bytes:
        return bytes(self.view[1:])


class Node(object):

    def __init__(self, sock: socket, key: bytes | None = None):
        self.sock = sock
        self.key = key
        self.send_q = q.Queue()
        self.recv_q = q.Queue()
        self.recv = self._recv()
        self.send = self._send()
        self.send_pending = False

    def _recv(self) -> Generator[int, None, None]:
        BUFFER_SIZE = 2 ** 16
        buff = bytearray(BUFFER_SIZE)
        view = memoryview(buff)
        a = b = c = d = 0
        while True:
            recvd = self.sock.recv_into(view[b:], BUFFER_SIZE - b)
            if not recvd:
                yield 0
            b += recvd
            while a < b:
                if not d:
                    if view[a] & 1:
                        if view[a] & 2:
                            if b - a < 4:
                                break
                            d = unpack_from('<I', view, a) >> 2
                            a += 4
                        if b - a < 2:
                            break
                        d = unpack_from('<H', view, a) >> 2
                        a += 2
                    d = view[a] >> 1
                    a += 1
                    if d:
                        msg = Message(d)
                else:
                    if d - c <= b - a:
                        msg.view[c:d] = view[a:a+d-c]
                        a += d - c
                        c = d = 0
                        if a == b:
                            a = b = 0
                        self.recv_q.put(msg)
                    else:
                        msg.view[c:c+b-a] = view[a:b]
                        c += b - a
                        a = b = 0
            if a > BUFFER_SIZE - 2048:
                view[:b-a] = view[a:b]
                a, b = 0, b - a

            yield recvd

    def _send(self) -> Generator[int, None, None]:
        BUFFER_SIZE = 2 ** 16
        buff = bytearray(BUFFER_SIZE)
        view = memoryview(buff)
        a = b = 0
        while True:
            while not self.send_q.empty():
                # process next queue item
                msg: Message = self.send_q.get()
                d = len(msg.buff)
                # pack encoded message length into buffer
                if d <= 127:                                    # 2 ** 7 - 1
                    view[b] = d << 1
                    b += 1
                elif d <= 16383:                                # 2 ** 14 - 1
                    pack_into('<H', view, b, (d << 2) | 1)
                    b += 2
                else:
                    pack_into('<I', view, b, (d << 2) | 3)
                    b += 4
                # buffer message if it fits
                if d <= BUFFER_SIZE - b:
                    view[b:b+d] = msg.view
                    b += d
                # otherwise send buffer then message
                else:
                    self.send_pending = True
                    # send buffer
                    while a < b:
                        sent = self.sock.send(view[a:b])
                        a += sent
                        yield sent
                    # reset buffer
                    a = b = c = 0
                    # send message
                    while c < d:
                        sent = self.sock.send(msg.view[c:d])
                        c += sent
                        if c == d:
                            self.send_pending = False
                        yield sent
            # send buffer after processing queue
            if a < b:
                self.send_pending = True
            while a < b:
                sent = self.sock.send(view[a:b])
                a += sent
                if a == b:
                    self.send_pending = False
                yield sent
            # reset buffer
            a = b = 0
                

class NodeManager(object):

    def __init__(self, key: bytes):
        self.key = key
        self.server: int | None = None
        self.nodes_map: dict[int, Node] = {}
        self.nodes_list: list[int] = []

    def serve(self, port: int) -> int:
        sock = socket()
        sock.bind(('', port))
        sock.listen(100)
        node = Node(sock=sock, key=self.key)
        fd = sock.fileno()
        self.server = fd
        self.nodes_map[fd] = node
        self.nodes_list.append(fd)
        return fd

    def accept(self, challenge: bytes) -> int:
        sock = self.nodes_map[self.server].sock.accept()[0]
        fd = sock.fileno()
        node = Node(sock)
        self.nodes_map[fd] = node
        self.nodes_list.append(fd)
        node.send_q.put(InitMessageBuilder(self.key, challenge).build())
        return fd

    def connect(self, addr: tuple[str, int], challenge: bytes) -> int:
        sock = create_connection(addr, timeout=1)
        node = Node(sock)
        fd = sock.fileno()
        self.nodes_map[fd] = node
        self.nodes_list.append(fd)
        node.send_q.put(InitMessageBuilder(self.key, challenge).build())
        return fd
    
    def close(self, fd: int) -> None:
        node = self.nodes_map.pop(fd)
        self.nodes_list.remove(fd)
        node.sock.close()


def parse_servers(filename: str) -> list[tuple[str, int]]:
    servers = []
    with open(filename, 'r') as file:
        for line in file:
            line = line.strip()
            match line.split(':'):
                case [host, port]:
                    servers.append((host, int(port)))
    return servers


def network(
    keypair: bytes,
    servers_filename: str = 'servers.txt',
    server_port: int | None = None
) -> None:
    public_key, private_key = keypair[:32], keypair[32:]
    nodes = NodeManager(public_key)
    challenge_pending: dict[int, bytes] = {}
    if server_port is not None:
        nodes.serve(server_port)
    servers = parse_servers(servers_filename)
    for addr in servers:
        challenge = urandom(32)
        fd = nodes.connect(addr, challenge)
        challenge_pending[fd] = challenge
    rlist, xlist = nodes.nodes_list, ()
    while True:
        wlist = [
            fd for fd, node in nodes.nodes_map.items()
            if not node.send_q.empty() or node.send_pending
        ]
        rr, wr, _ = select(rlist, wlist, xlist, 1)
        for fd in rr:
            if fd == nodes.server:
                challenge = urandom(32)
                client = nodes.accept(challenge)
                challenge_pending[client] = challenge
            else:
                node = nodes.nodes_map[fd]
                recvd = next(node.recv)
                if not recvd:
                    nodes.close(fd)
                while not node.recv_q.empty():
                    msg: Message = node.recv_q.get()
                    match msg.view[0]:
                        case MessageEnum.INIT.value:
                            pass
                        case MessageEnum.CHALLENGE_ANSWER.value:
                            pass
                        