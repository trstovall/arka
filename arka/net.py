
import asyncio
import socket
import struct
import logging
import random

from os import urandom
from .crypto import keypair, keccak_800, sign, verify


# Constants
TIMEOUT = 10  # seconds
MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds
BACKOFF_MULTIPLIER = 1.5
ARKA_BANNER = b'arka'
MAX_MESSAGE_SIZE = 2**23

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


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def msg_init(peer_id: bytes, challenge: bytes) -> bytes:
        return b''.join([
            bytes([MSG_INIT]), ARKA_BANNER, peer_id, challenge
        ])


def msg_challenge_answer(answer: bytes) -> bytes:
        return bytes([MSG_CHALLENGE_ANSWER]) + answer


def msg_pub_peers_update(added: set, removed: set) -> bytes:
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


def msg_meet_request(neighbor: bytes) -> bytes:
    return bytes([MSG_MEET_REQUEST]) + neighbor


def msg_meet_intro(neighbor: bytes, addr: tuple[str, int]) -> bytes:
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
    def peer_id(self) -> bytes:
        return bytes(self.view[5:37])
    
    @property
    def challenge(self) -> bytes:
        return bytes(self.view[37:69])


class ChallengeAnswerMessage(Message):

    def __init__(self, msg: bytes | bytearray):
        if len(msg) != 65:
            raise ValueError("msg argument for ChallengeAnswerMessage must be 65 bytes long.")
        super().__init__(self, msg)

    @property
    def answer(self) -> bytes:
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
    def added(self) -> set[bytes]:
        start, end = self.offset, self.offset + 32 * self.num_added
        return {bytes(self.view[i:i+32]) for i in range(start, end, 32)}

    @property
    def removed(self) -> set[bytes]:
        start = self.offset + 32 * self.num_added
        end = start + 32 * self.num_removed
        return {bytes(self.view[i:i+32]) for i in range(start, end, 32)}


class MeetRequestMessage(Message):

    def __init__(self, msg: bytes | bytearray):
        if len(msg) != 33:
            raise ValueError('Invalid message size for `MeetRequestMessage`.')
        super().__init__(self, msg)
    
    @property
    def neighbor(self) -> bytes:
        return bytes(self.view[1:33])


class MeetIntroMessage(Message):

    @property
    def neighbor(self) -> bytes:
        n = bytes(self.view[2:34])
        if len(n) != 32:
            raise ValueError('Invalid message size for `MeetIntroMessage`.')
        return n

    @property
    def addr(self) -> tuple[str, int]:
        host = bytes(self.view[34:-2]).decode()
        port = struct.unpack('<H', self.msg[-2:])[0]
        return host, port


class Peer(object):
    """A peer in a P2P network using a binary API with asyncio."""
    
    def __init__(self, keypair: bytes, local_port: int = 0, max_connections: int = 50):
        self.keypair = keypair
        self.peer_id = keypair[32:]
        self.local_port = local_port
        self.max_connections = max_connections
        self.peers: dict[bytes, tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}
        self.neighbors: dict[bytes, set[bytes]] = {}  # peer_id -> set of their connected peers
        self.running = False
        self.server = None
        self.loop = asyncio.get_event_loop()
        self.writer_q: asyncio.Queue[asyncio.StreamWriter] = asyncio.Queue()

    ### Server and Connection Management

    async def start_server(self):
        """Start the asyncio server."""
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('::', self.local_port))
        sock.listen(10)
        sock.setblocking(False)
        self.server = await asyncio.start_server(self.handle_connection, sock=sock)
        self.local_port = sock.getsockname()[1]
        logging.info(f'Peer {self.peer_id} started on port {self.local_port}')
        async with self.server:
            await self.server.serve_forever()

    async def attempt_connect(self, addr: tuple[str, int]) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
        """Connect to a peer with retries."""
        delay = RETRY_DELAY
        for attempt in range(MAX_RETRIES):
            try:
                # Bind client socket to reused local port for NAT consistency
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(('::', self.local_port))
                sock.setblocking(False)

                # Connect to the remote peer
                await self.loop.sock_connect(sock, addr)

                # Return asyncio streams
                reader = asyncio.StreamReader()
                writer = asyncio.StreamWriter(sock, reader, self.loop)
                return reader, writer
            except Exception as e:
                if attempt + 1 == MAX_RETRIES:
                    return
                await asyncio.sleep(delay)
                delay *= BACKOFF_MULTIPLIER

    ### Communication

    async def send_message(self, writer: asyncio.StreamWriter, msg: bytes | bytearray):
        msg_len = len(msg)
        try:
            # send message length
            if msg_len < 0x80:
                msg_len = bytes([msg_len << 1])
            elif msg_len < 0x4000:
                msg_len = struct.pack('<H', (msg_len << 2) | 1)
            elif msg_len <= MAX_MESSAGE_SIZE:
                msg_len = struct.pack('<I', (msg_len << 2) | 3)
            else:
                raise ValueError('Message is too long to send.')
            writer.write(msg_len)
            # send message
            writer.write(msg)
            await self.writer_q.put(writer)
        except Exception as e:
            logging.error(f"Send failed: {e}")
            raise

    async def recv_message(self, reader: asyncio.StreamReader) -> bytes | None:
        try:
            length_bytes = await reader.readexactly(1)
            msg_len = length_bytes[0]
            if msg_len & 1:
                if msg_len & 3:
                    length_bytes += await reader.readexactly(3)
                    msg_len = struct.unpack('<I', length_bytes)[0] >> 2
                else:
                    length_bytes += await reader.readexactly(1)
                    msg_len = struct.unpack('<H', length_bytes)[0] >> 2
            else:
                msg_len >>= 1
            if 0 < msg_len <= MAX_MESSAGE_SIZE:
                return await reader.readexactly(msg_len)
        except Exception as e:
            logging.error(f"recv failed: {e}")

    async def flush_writers(self):
        while self.running:
            writer: asyncio.StreamWriter = await self.writer_q.get()
            if not writer:
                break
            try:
                await writer.drain()
            except Exception as e:
                pass

    ### Connection Handling

    async def setup_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bytes | None:
        # send init
        local_challenge = urandom(32)
        msg = msg_init(self.peer_id, local_challenge)
        await self.send_message(writer, msg)
        # recv init
        msg = await asyncio.wait_for(
            self.recv_message(reader), timeout=TIMEOUT
        )
        if not msg or msg[0] != MSG_INIT:
            return
        msg = InitMessage(msg)
        peer_id = msg.peer_id
        remote_challenge = msg.challenge
        if peer_id in self.peers:
            return
        # send challenge answer
        challenges = sorted([local_challenge, remote_challenge])
        challenge = keccak_800(b''.join(challenges))
        local_answer = await self.loop.run_in_executor(None, sign, self.keypair, challenge)
        msg = msg_challenge_answer(local_answer)
        await self.send_message(writer, msg)
        # recv challenge answer
        msg = await asyncio.wait_for(
            self.recv_message(reader), timeout=TIMEOUT
        )
        if not msg or msg[0] != MSG_CHALLENGE_ANSWER:
            return
        remote_answer = ChallengeAnswerMessage(msg).answer
        if not verify(peer_id, remote_answer + challenge):
            return

        self.peers[peer_id] = (reader, writer)
        self.neighbors[peer_id] = set()

        # broadcast peer set updates
        msg = msg_pub_peers_update(added={peer_id})
        for peer, (r, w) in self.peers.items():
            if peer != peer_id:
                await self.send_message(w, msg)
        peers = set(self.peers.keys()) - {peer_id}
        msg = msg_pub_peers_update(added=peers)
        await self.send_message(writer, msg)
        return peer_id

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle an incoming connection."""
        try:
            peer_id = await self.setup_connection(reader, writer)
            if not peer_id:
                return

            # Handle messages
            while self.running:
                msg = await self.recv_message(reader)
                if not msg:
                    break
                match msg[0]:
                    case int(MSG_PUB_PEERS_UPDATE):
                        msg = PubPeersUpdateMessage(msg)
                        self.neighbors |= msg.added
                        self.neighbors -= msg.removed
                    case int(MSG_MEET_REQUEST):
                        msg = MeetRequestMessage(msg)
                        await self.handle_meet_request(peer_id, msg.neighbor)
                    case int(MSG_MEET_INTRO):
                        msg = MeetIntroMessage(msg)
                        await self.handle_meet_intro(msg.neighbor, msg.addr)

        except Exception as e:
            logging.error(f'Error while processing connection: {e}')
        finally:
            if peer_id in self.peers:
                del self.peers[peer_id]
                if peer_id in self.neighbors:
                    del self.neighbors[peer_id]
                if self.running:
                    # broadcast peer disconnect
                    msg = msg_pub_peers_update(removed={peer_id})
                    for r, w in self.peers.values():
                        await self.send_message(w, msg)
            writer.close()
            await writer.wait_closed()

    ### Network Operations

    async def connect_to_peer(self, addr: tuple[str, int]):
        """Connect to a peer."""
        if len(self.peers) >= self.max_connections:
            return
        conn = await self.attempt_connect(addr)
        if not conn:
            return
        asyncio.create_task(self.handle_connection(*conn))

    async def handle_meet_request(self, requester_id: bytes, target_id: bytes):
        """Facilitate a connection between two peers."""
        if target_id not in self.peers:
            return
        req_writer = self.peers[requester_id][1]
        tgt_writer = self.peers[target_id][1]
        req_addr = req_writer.get_extra_info('peername')
        tgt_addr = tgt_writer.get_extra_info('peername')

        msg = msg_meet_intro(target_id, tgt_addr)
        await self.send_message(req_writer, msg)
        msg = msg_meet_intro(requester_id, req_addr)
        await self.send_message(tgt_writer, msg)
        logging.info(f"Introduced {requester_id} to {target_id}")

    async def handle_meet_intro(self, neighbor: bytes, addr: tuple[str, int]):
        """Handle an introduction to connect to a new peer."""
        if (len(self.peers) < self.max_connections
            and neighbor not in self.peers
        ):
            await self.connect_to_peer(addr)

    async def expand_network(self):
        """Expand the network by connecting to a random neighbor."""
        while self.running:
            if not self.peers or len(self.peers) >= self.max_connections:
                await asyncio.sleep(5)
                continue

            peer = random.choice(list(self.peers.keys()))
            neighbor = random.choice(list(self.neighbors[peer]))
            if not neighbor:
                await asyncio.sleep(5)
                continue

            writer = self.peers[peer][1]
            msg = msg_meet_request(neighbor)
            await self.send_message(writer, msg)
            await asyncio.sleep(5)

    ### Lifecycle

    async def start(self, initial_peers: list[tuple[str, int]] = []):
        """Start the peer."""
        self.running = True
        tasks = [self.start_server(), self.expand_network(), self.flush_writers()]
        for peer in initial_peers:
            tasks.append(self.connect_to_peer(peer))
        await asyncio.gather(*tasks)

    async def stop(self):
        """Stop the peer."""
        self.running = False
        await self.writer_q.put(None)
        for _, writer in self.peers.values():
            writer.close()
            await writer.wait_closed()
        self.peers.clear()
        self.neighbors.clear()
        if self.server:
            self.server.close()
            await self.server.wait_closed()

# Example usage
async def main():
    peer1 = Peer(keypair(urandom(32)))
    peer2 = Peer(keypair(urandom(32)))
    peer3 = Peer(keypair(urandom(32)))

    asyncio.create_task(peer1.start())
    await asyncio.sleep(1)
    asyncio.create_task(peer2.start([("::1", peer1.local_port)]))
    await asyncio.sleep(1)
    asyncio.create_task(peer3.start([("::1", peer2.local_port)]))

    await asyncio.sleep(20)
    await peer1.stop()
    await peer2.stop()
    await peer3.stop()

if __name__ == "__main__":
    asyncio.run(main())
