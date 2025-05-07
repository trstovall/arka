
from arka import net_udp as net

import asyncio
import pytest_asyncio
import pytest
import random


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

    def register(self, addr: net.Address, sock: net.Socket):
        self._socks[addr] = sock

    def sendto(self, data: bytes, addr: net.Address):
        if addr in self._socks:
            if self._debug:
                print(f'to: {addr}, {inspect(data)}')
            if self._jitter is None:
                self._loop.call_soon(
                    self._socks[addr].datagram_received, data
                )
            else:
                self._loop.call_later(
                    self._jitter * random.random(),
                    self._socks[addr].datagram_received,
                    data
                )

    def close(self):
        self._socks.clear()


@pytest_asyncio.fixture
def transport(event_loop):
    return MockTransport(event_loop)


@pytest_asyncio.fixture
def socket_pair(transport):
    A = net.Socket(('::1', 1), transport)
    B = net.Socket(('::1', 0), transport)
    transport.register(('::1', 0), A)
    transport.register(('::1', 1), B)
    yield A, B
    A.close()
    B.close()


def socket_pair_t(pair) -> tuple[net.Socket, net.Socket]:
    return pair


@pytest.mark.asyncio
async def test_handshake(socket_pair: tuple[net.Socket, net.Socket]):
    A, B = socket_pair
    # Initiate from A
    A.connect()
    # Let SYN/SYN-ACK/ACK exchange
    await asyncio.sleep(0.05)
    assert None not in (A._peer_ack, A._ack)
    assert None not in (B._peer_ack, B._ack)


@pytest.mark.asyncio
async def test_send_and_recv(socket_pair: tuple[net.Socket, net.Socket]):
    A, B = socket_pair
    A.connect()
    await asyncio.sleep(0.05)
    # Send small message
    msg = b'hello'
    await A.send(msg)
    got = await B.recv()
    assert got == msg
    await B.send(got)
    echo = await A.recv()
    assert echo == msg


@pytest.mark.asyncio
async def test_send_and_recv_large(socket_pair: tuple[net.Socket, net.Socket]):
    A, B = socket_pair
    A.connect()
    await asyncio.sleep(0.05)
    # Send large message
    msg = b'x' * (A.MAX_PAYLOAD * 2 + 50)
    await A.send(msg)
    got = await B.recv()
    assert got == msg
    await B.send(got)
    echo = await A.recv()
    await asyncio.sleep(.1)
    assert echo == msg


# @pytest.mark.skip
@pytest.mark.asyncio
async def test_send_and_recv_max(socket_pair: tuple[net.Socket, net.Socket]):
    A, B = socket_pair
    A.connect()
    await asyncio.sleep(0.05)
    # Send max message
    msg = b'x' * A.MAX_MSG_SIZE
    await A.send(msg)
    got = await B.recv()
    assert got == msg
    await B.send(got)
    echo = await A.recv()
    assert echo == msg


@pytest.mark.asyncio
async def test_malformed_packet_closes(socket_pair: tuple[net.Socket, net.Socket]):
    A, B = socket_pair
    A.connect()
    await asyncio.sleep(0.05)
    # Send truncated header
    A.transport.sendto(b'\x00\x01', A.peer)
    # B should detect malformed and close
    await asyncio.sleep(0.01)
    assert B.closed is True


@pytest.mark.asyncio
async def test_window_enforcement(socket_pair: tuple[net.Socket, net.Socket]):
    A, B = socket_pair
    A.connect()
    await asyncio.sleep(0.05)
    # Craft out-of-window sequence for B
    bad_seq = (B._ack or 0) + B.MAX_RECV_WINDOW + 1
    hdr = B.HEADER.pack(bad_seq, A._seq, net.Socket.FLAG_ACK)
    B.datagram_received(hdr + b'x')
    assert bad_seq not in B._recd


def test_seq_lt():
    # seq_lt should handle wraparound
    a = 2 ** 32 - 2
    b = 1
    assert net.seq_lt(a, b) is True
    assert net.seq_lt(b, a) is False


@pytest.mark.asyncio
async def test_seq_wrap(socket_pair: tuple[net.Socket, net.Socket]):
    A, B = socket_pair
    A._seq = 2 ** 32 - 100
    A.connect()
    await asyncio.sleep(0.05)
    # Send large message
    msg = b'x' * A.MAX_PAYLOAD * 200 + 50
    await A.send(msg)
    got = await B.recv()
    assert got == msg
    await B.send(got)
    echo = await A.recv()
    assert echo == msg


@pytest.mark.asyncio
async def test_jitter(socket_pair: tuple[net.Socket, net.Socket]):
    A, B = socket_pair
    A.connect()
    await asyncio.sleep(0.05)
    # Send large message
    A.transport._jitter = 0.05
    msg = b'x' * A.MAX_MSG_SIZE
    await A.send(msg)
    got = await B.recv()
    assert got == msg
    await B.send(got)
    echo = await A.recv()
    assert echo == msg
