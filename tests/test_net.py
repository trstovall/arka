
from arka import net
from arka import broker

import asyncio
import pytest_asyncio
import pytest
import random


skip_all = False


def inspect(data):
    if len(data) < 9:
        return f'{len(data)}'
    return 'seq: {seq}, ack: {ack}, flags: {flags}, data: {data}'.format(
        seq=int.from_bytes(data[:4], 'little') & 0xff,
        ack=int.from_bytes(data[4:8], 'little') & 0xff,
        flags=int.from_bytes(data[8:9], 'little') & 0xff,
        data=len(data) - 9
    )


class MockTransport:

    def __init__(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop
        self._socks: dict[net.Address, net.Socket] = {}
        self._debug: bool = False
        self._jitter: float | None = None
        self._drop: float | None = None
        self._latency: float = 0.001

    def register(self, addr: net.Address, sock: net.Socket):
        self._socks[addr] = sock

    def sendto(self, data: bytes, addr: net.Address):
        addr = addr[:2]
        if addr in self._socks:
            if self._drop and random.random() < self._drop:
                return
            if self._debug:
                print(f'to: {addr}, {inspect(data)}')
            if self._jitter is None and not self._latency:
                self._loop.create_task(
                    self.to_task(self._socks[addr].datagram_received, data)
                )
            else:
                self._loop.call_later(
                    self._latency + (self._jitter or 0) * random.random(),
                    self._socks[addr].datagram_received,
                    data
                )

    async def to_task(self, func, *args):
        func(*args)


@pytest_asyncio.fixture
def transport(event_loop):
    return MockTransport(event_loop)


@pytest_asyncio.fixture
def socket_pair(transport):
    A = net.Socket(('::1', 1), transport)
    B = net.Socket(('::1', 0), transport)
    transport.register(('::1', 0), A)
    transport.register(('::1', 1), B)
    return A, B


def build_futures(pair: tuple[net.Socket, net.Socket]) -> tuple[
    asyncio.Future, asyncio.Future, asyncio.Future, asyncio.Future
]:
    A, B = pair
    A_connected, B_connected = asyncio.Future(), asyncio.Future()
    A_closed, B_closed = asyncio.Future(), asyncio.Future()
    A.on_connect = lambda x: A_connected.set_result(None)
    B.on_connect = lambda x: B_connected.set_result(None)
    A.on_close = lambda x: A_closed.set_result(None)
    B.on_close = lambda x: B_closed.set_result(None)
    return A_connected, B_connected, A_closed, B_closed


@pytest.mark.skipif(skip_all, reason='')
@pytest.mark.asyncio
async def test_handshake(socket_pair: tuple[net.Socket, net.Socket]):
    A, B = socket_pair
    A.transport._debug = True
    A_connected, B_connected, A_closed, B_closed = build_futures(socket_pair)
    # Initiate connect from A
    A.connect()
    # Let SYN/SYN-ACK/ACK exchange
    await asyncio.gather(A_connected, B_connected)
    assert A._state == A.STATE_ESTABLISHED
    assert B._state == B.STATE_ESTABLISHED
    # Initiate disconnect from B
    B.close()
    # Let FIN/FIN-ACK/ACK exchange
    await asyncio.gather(A_closed, B_closed)
    assert A._state == A.STATE_CLOSED
    assert B._state == B.STATE_CLOSED


@pytest.mark.skipif(skip_all, reason='')
@pytest.mark.asyncio
async def test_simultaneous_syn(socket_pair: tuple[net.Socket, net.Socket]):
    A, B = socket_pair
    A_connected, B_connected, A_closed, B_closed = build_futures(socket_pair)
    # Initiate connect from A
    A.connect()
    B.connect()
    # Let SYN/SYN-ACK/ACK exchange
    await asyncio.gather(A_connected, B_connected)
    assert A._state == A.STATE_ESTABLISHED
    assert B._state == B.STATE_ESTABLISHED
    # Initiate disconnect from B
    B.close()
    # Let FIN/FIN-ACK/ACK exchange
    await asyncio.gather(A_closed, B_closed)
    assert A._state == A.STATE_CLOSED
    assert B._state == B.STATE_CLOSED


@pytest.mark.skipif(skip_all, reason='')
@pytest.mark.asyncio
async def test_simultaneous_fin(socket_pair: tuple[net.Socket, net.Socket]):
    A, B = socket_pair
    A_connected, B_connected, A_closed, B_closed = build_futures(socket_pair)
    # Initiate connect from A
    A.connect()
    # Let SYN/SYN-ACK/ACK exchange
    await asyncio.gather(A_connected, B_connected)
    assert A._state == A.STATE_ESTABLISHED
    assert B._state == B.STATE_ESTABLISHED
    # Initiate disconnect from B
    A.close()
    B.close()
    # Let FIN/FIN-ACK/ACK exchange
    await asyncio.gather(A_closed, B_closed)
    assert A._state == A.STATE_CLOSED
    assert B._state == B.STATE_CLOSED


@pytest.mark.skipif(skip_all, reason='')
@pytest.mark.asyncio
async def test_send_and_recv(socket_pair: tuple[net.Socket, net.Socket]):
    A, B = socket_pair
    A.transport._debug = True
    A_connected, B_connected, A_closed, B_closed = build_futures(socket_pair)
    # Connect
    A.connect()
    await asyncio.gather(A_connected, B_connected)
    assert A._state == A.STATE_ESTABLISHED
    assert B._state == B.STATE_ESTABLISHED
    # Send small message
    msg = b'hello'
    await A.send(msg)
    got = await B.recv()
    assert got == msg
    await B.send(got)
    echo = await A.recv()
    assert echo == msg
    # Close
    B.close()
    await asyncio.gather(A_closed, B_closed)
    assert A._state == A.STATE_CLOSED
    assert B._state == B.STATE_CLOSED


@pytest.mark.skipif(skip_all, reason='')
@pytest.mark.asyncio
async def test_send_and_recv_large(socket_pair: tuple[net.Socket, net.Socket]):
    A, B = socket_pair
    A.transport._debug = True
    A_connected, B_connected, A_closed, B_closed = build_futures(socket_pair)
    # Connect
    A.connect()
    await asyncio.gather(A_connected, B_connected)
    assert A._state == A.STATE_ESTABLISHED
    assert B._state == B.STATE_ESTABLISHED
    # Send large message
    msg = b'x' * (A.MAX_PAYLOAD * 10 + 50)
    await A.send(msg)
    got = await B.recv()
    assert got == msg
    await B.send(got)
    echo = await A.recv()
    assert echo == msg
    # Close
    B.close()
    await asyncio.gather(A_closed, B_closed)
    assert A._state == A.STATE_CLOSED
    assert B._state == B.STATE_CLOSED


@pytest.mark.skipif(skip_all, reason='')
@pytest.mark.asyncio
async def test_send_and_recv_max(socket_pair: tuple[net.Socket, net.Socket]):
    A, B = socket_pair
    A.transport._debug = True
    A_connected, B_connected, A_closed, B_closed = build_futures(socket_pair)
    # Connect
    A.connect()
    await asyncio.gather(A_connected, B_connected)
    assert A._state == A.STATE_ESTABLISHED
    assert B._state == B.STATE_ESTABLISHED
    # Send max message
    msg = b'x' * A.MAX_MSG_SIZE
    await A.send(msg)
    got = await B.recv()
    assert got == msg
    await B.send(got)
    echo = await A.recv()
    assert echo == msg
    # Close
    B.close()
    await asyncio.gather(A_closed, B_closed)
    assert A._state == A.STATE_CLOSED
    assert B._state == B.STATE_CLOSED


@pytest.mark.skipif(skip_all, reason='')
@pytest.mark.asyncio
async def test_malformed_packet_closes(socket_pair: tuple[net.Socket, net.Socket]):
    A, B = socket_pair
    A_connected, B_connected, A_closed, B_closed = build_futures(socket_pair)
    # Connect
    A.connect()
    await asyncio.gather(A_connected, B_connected)
    assert A._state == A.STATE_ESTABLISHED
    assert B._state == B.STATE_ESTABLISHED
    # Send truncated header
    A.transport.sendto(b'\x00\x01', A.peer)
    # B should detect malformed and close
    await asyncio.gather(A_closed, B_closed)
    assert A._state == A.STATE_CLOSED
    assert B._state == B.STATE_CLOSED


@pytest.mark.skipif(skip_all, reason='')
@pytest.mark.asyncio
async def test_window_enforcement(socket_pair: tuple[net.Socket, net.Socket]):
    A, B = socket_pair
    A_connected, B_connected, A_closed, B_closed = build_futures(socket_pair)
    # Connect
    A.connect()
    await asyncio.gather(A_connected, B_connected)
    assert A._state == A.STATE_ESTABLISHED
    assert B._state == B.STATE_ESTABLISHED
     # Craft out-of-window sequence for B
    bad_seq = (A._ack or 0) + A.MAX_RECV_WINDOW + 1
    hdr = B.HEADER.pack(bad_seq, A._seq, net.Socket.FLAG_ACK)
    A.datagram_received(hdr + b'x')
    assert bad_seq not in A._recd
    assert A._state == A.STATE_ESTABLISHED
    assert B._state == B.STATE_ESTABLISHED
    # Close
    B.close()
    await asyncio.gather(A_closed, B_closed)
    assert A._state == A.STATE_CLOSED
    assert B._state == B.STATE_CLOSED


@pytest.mark.skipif(skip_all, reason='')
def test_seq_lt():
    # seq_lt should handle wraparound
    a = 2 ** 32 - 2
    b = 1
    assert net.seq_lt(a, b) is True
    assert net.seq_lt(b, a) is False


@pytest.mark.skipif(skip_all, reason='')
@pytest.mark.asyncio
async def test_seq_wrap(socket_pair: tuple[net.Socket, net.Socket]):
    A, B = socket_pair
    A_connected, B_connected, A_closed, B_closed = build_futures(socket_pair)
    # Connect
    A.connect()
    await asyncio.gather(A_connected, B_connected)
    assert A._state == A.STATE_ESTABLISHED
    assert B._state == B.STATE_ESTABLISHED
    # Send wrap-around message
    msg = b'x' * (A.MAX_PAYLOAD * 200 + 50)
    await A.send(msg)
    got = await B.recv()
    assert got == msg
    await B.send(got)
    echo = await A.recv()
    assert echo == msg
    # Close
    B.close()
    await asyncio.gather(A_closed, B_closed)
    assert A._state == A.STATE_CLOSED
    assert B._state == B.STATE_CLOSED


@pytest.mark.skipif(skip_all, reason='')
@pytest.mark.asyncio
async def test_jitter(socket_pair: tuple[net.Socket, net.Socket]):
    A, B = socket_pair
    A_connected, B_connected, A_closed, B_closed = build_futures(socket_pair)
    # Connect
    A.connect()
    await asyncio.gather(A_connected, B_connected)
    assert A._state == A.STATE_ESTABLISHED
    assert B._state == B.STATE_ESTABLISHED
    A.transport._jitter = 0.01      # 10 ms jitter
    msg = b'x' * A.MAX_MSG_SIZE
    await A.send(msg)
    got = await B.recv()
    assert got == msg
    await B.send(got)
    echo = await A.recv()
    assert echo == msg
    # Close
    B.close()
    await asyncio.gather(A_closed, B_closed)
    assert A._state == A.STATE_CLOSED
    assert B._state == B.STATE_CLOSED


@pytest.mark.skipif(skip_all, reason='')
@pytest.mark.asyncio
async def test_dropped_packets(socket_pair: tuple[net.Socket, net.Socket]):
    A, B = socket_pair
    A_connected, B_connected, A_closed, B_closed = build_futures(socket_pair)
    A.transport._debug = True
    A.transport._drop = 0.1         # 10% dropped packets
    A.transport._latency = .05      # 50 ms
    # Connect
    A.connect()
    await asyncio.gather(A_connected, B_connected)
    assert A._state == A.STATE_ESTABLISHED
    assert B._state == B.STATE_ESTABLISHED
    # msg = b'x' * A.MAX_MSG_SIZE
    msg = b'x' * (A.MAX_PAYLOAD * 10 + 50)
    await A.send(msg)
    got = await B.recv()
    assert got == msg
    await B.send(got)
    echo = await A.recv()
    assert echo == msg
    # Close
    B.close()
    await asyncio.gather(A_closed, B_closed)
    assert A._state == A.STATE_CLOSED
    assert B._state == B.STATE_CLOSED


@pytest.mark.skipif(skip_all, reason='')
@pytest.mark.asyncio
async def test_mesh():
    async def handle_q(event_q: asyncio.Queue[broker.AbstractBrokerEvent]):
        while True:
            match await event_q.get():
                case broker.PeerConnected() as event:
                    print(f'{event.addr} connected!')
                case broker.PeerDisconnected() as event:
                    print(f'{event.addr} disconnected!')
    q = asyncio.Queue()
    bA = broker.Broker()
    bB = broker.Broker()
    bC = broker.Broker()
    bA.sub(broker.PeerConnected, q)
    bB.sub(broker.PeerConnected, q)
    bC.sub(broker.PeerConnected, q)
    bA.sub(broker.PeerDisconnected, q)
    bB.sub(broker.PeerDisconnected, q)
    bC.sub(broker.PeerDisconnected, q)
    handler = asyncio.create_task(handle_q(q))
    A = net.Mesh(('::1', 5000), bA)
    await A.start()
    B = net.Mesh(('::1', 5001), bB, bootstrap=[('::1', 5000)])
    await B.start()
    C = net.Mesh(('::1', 5002), bC, bootstrap=[('::1', 5000)])
    await C.start()
    await asyncio.sleep(15)
    await A.stop()
    await asyncio.sleep(1)
    await B.stop()
    await asyncio.sleep(1)
    await C.stop()
    await asyncio.sleep(1)
    handler.cancel()
