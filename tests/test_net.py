
from arka import net_udp as net

import asyncio
import pytest

class MockTransport:

    def __init__(self):
        self._socks: dict[net.Address, net.Socket] = {}
    
    def register(self, addr: net.Address, sock: net.Socket):
        self._socks[addr] = sock
    
    def sendto(self, data: bytes, addr: net.Address):
        if addr in self._socks:
            asyncio.get_running_loop().call_soon(
                self._socks[addr].datagram_received, data, addr
            )

    def close(self):
        self._socks.clear()


@pytest.fixture
def loop():
    return asyncio.get_running_loop()


@pytest.fixture
def transport():
    return MockTransport()


@pytest.fixture
def socket_pair(loop, transport):
    A = net.Socket(('::1', 1), transport)
    B = net.Socket(('::1', 0), transport)
    transport.register(('::1', 0), A)
    transport.register(('::1', 1), B)
    return A, B


@pytest.mark.asyncio
async def test_handshake(socket_pair):
    A, B = socket_pair
    # Initiate from A
    A.connect()
    # Let SYN/SYN-ACK/ACK exchange
    await asyncio.sleep(0.05)
    assert None not in (A._peer_ack, A._ack)
    assert None not in (B._peer_ack, B._ack)


@pytest.mark.asyncio
async def test_send_and_recv(socket_pair):
    A, B = socket_pair
    A.connect()
    await asyncio.sleep(0.05)
    # Send small message
    msg = b'hello'
    await A.send(msg)
    got = await B.recv()
    assert got == msg
    B.send(got)
    echo = await A.recv()
    assert echo == msg


@pytest.mark.asyncio
async def test_send_and_recv_large(socket_pair):
    A, B = socket_pair
    A.connect()
    await asyncio.sleep(0.05)
    # Send large message
    msg = b'x' * (A.MAX_PAYLOAD * 2 + 50)
    await A.send(msg)
    got = await B.recv()
    assert got == msg
    B.send(got)
    echo = await A.recv()
    assert echo == msg


@pytest.mark.asyncio
async def test_send_and_recv_max(socket_pair):
    A, B = socket_pair
    A.connect()
    await asyncio.sleep(0.05)
    # Send max message
    msg = b'x' * A.MAX_MSG_SIZE
    await A.send(msg)
    got = await B.recv()
    assert got == msg
    B.send(got)
    echo = await A.recv()
    assert echo == msg


@pytest.mark.asyncio
async def test_readexactly_incomplete(socket_pair):
    A, B = socket_pair
    A.connect()
    await asyncio.sleep(0.05)
    await A.send(b'abc')
    # Attempt to read more than available
    with pytest.raises(asyncio.IncompleteReadError):
        await asyncio.wait_for(B._reader.readexactly(10), timeout=0.1)


@pytest.mark.asyncio
async def test_malformed_packet_closes(socket_pair):
    A, B = socket_pair
    A.connect()
    await asyncio.sleep(0.05)
    # Send truncated header
    A.transport.sendto(b'\x00\x01', A.peer)
    # B should detect malformed and close
    await asyncio.sleep(0.01)
    assert B.closed is True


@pytest.mark.asyncio
async def test_window_enforcement(socket_pair):
    A, B = socket_pair
    A.connect()
    await asyncio.sleep(0.05)
    # Craft out-of-window sequence for B
    bad_seq = (B._ack or 0) + B.MAX_RECV_WINDOW + 1
    hdr = B.HEADER.pack(bad_seq, A._seq, net.Socket.FLAG_ACK)
    B.datagram_received(hdr + b'x')
    assert bad_seq not in B._recd


def test_seq_wrap():
    # seq_lt should handle wraparound
    a = 2 ** 32 - 2
    b = 1
    assert net.seq_lt(a, b) is True
    assert net.seq_lt(b, a) is False
