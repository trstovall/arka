"""Persistent critbit codecs and batch database coordinator.

Storage format v1 follows block.py's owned-byte, encode/decode conventions:
little-endian metadata, explicit tags/lengths, exact bounded decoding. Domain
values retain block.py encodings; numeric proposal *keys* are big-endian.

Allocation options at billions of records
----------------------------------------
Implemented: append-only, eight-byte aligned records, tracked by per-file dual
allocation checkpoints. Immutable paths permit cheap root snapshots. Abandoned
allocations leak space safely; they are never reused. Bounded mmap windows avoid
mapping terabytes or retaining one Python object per record. A binary tree with
N leaves has N-1 branches: measure branch/leaf bytes and copy-on-write amplification,
not merely key count. The current critbit batch staging is O(batch paths) RAM;
stream bounded batches, not a billion-record dictionary, for ingestion.

Alternatives: size-class slabs for fixed-size branches reduce fragmentation but
need durable bitmaps; buddy extents suit large variable leaves but waste rounded
space; segmented append plus copying compaction gives sequential I/O but requires
root relocation. A production allocator can combine branch slabs and leaf extents.
All reuse requires tracing every retained canonical/auxiliary/history root and
reader pin, with versioned allocator metadata committed alongside roots. Never
free an old path solely because the newest root no longer reaches it.

This first implementation deliberately has no reclamation, journal checkpointing,
network adapter or consensus parser. Journal recovery is linear in commit count,
not tree size; bound startup time later with durable journal checkpoints. Mmap
window count is bounded, but node reads still have mapping/cache overhead. Benchmark
locality, random I/O and write amplification before claiming billion-record speed.
At one billion leaves, even a 40-byte ordinary branch consumes about 40 GB;
keys, values, framing, alignment and retained copy-on-write generations are extra.
Use a 64-bit process and filesystem with sufficient sparse/large-file support.
Allocation bookkeeping is constant-size per checkpoint, not a billion-entry
bitmap in Python. The current 16 MiB record limit rejects oversized values before
allocation; out-of-line large-value extents would require a new format version.

Example (already validated block changes, not transaction parsing):
    schema = SCHEMAS['arka_utxos']
    patch = Patch('arka_utxos', ((schema.encode_key(ref),
                                 schema.encode_value(output)),))
    db = Database()
    generation = db.commit((patch,), db.generation, block_hash.encode())
    db.close()
The async Coordinator takes Request objects containing such patches and produces
Response objects on its output queue. Augmented entries use critbit.Update.

Commit: flush node mappings, fsync tree files and their allocation checkpoints,
then append/fsync a checksummed root-set journal record. Only then expose roots.
Recovery ignores an incomplete final journal record, rejects checksum corruption,
and verifies referenced file identities/extents/roots. Directory synchronization
is performed on POSIX; Windows directory-entry power-loss guarantees need a native
implementation and fault testing. File fsync is not proof against hardware that
ignores flush commands. This module is not yet power-outage-qualified on Windows.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import json
import mmap
import os
from pathlib import Path
import struct
import uuid
import zlib

from arka.critbit import Branch, Critbit, ExecutiveRank, Kind, Leaf, TREE_KINDS, Update

KINDS = (Kind.MAP, Kind.SUM, Kind.MAX)
HEADER_SIZE = 4096
MAX_RECORD = 16 * 1024 * 1024
WINDOW = 8 * 1024 * 1024


def _bytes(value):
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError('Expected bytes')
    return bytes(value)


def _write(file, data):
    view = memoryview(data)
    while view:
        count = file.write(view)
        if count is None or count <= 0:
            raise OSError('Short write')
        view = view[count:]


def _uint(value):
    if type(value) is not int or value < 0:
        raise ValueError('Expected unsigned integer')
    width = max(1, (value.bit_length() + 7) // 8)
    if width > 256:
        raise ValueError('Aggregate exceeds codec limit of 2048 bits')
    return struct.pack('<H', width) + value.to_bytes(width, 'little')


class _Reader:
    def __init__(self, data):
        self.data, self.offset = _bytes(data), 0

    def take(self, size):
        if size < 0 or size > len(self.data) - self.offset:
            raise ValueError('Truncated record')
        result = self.data[self.offset:self.offset + size]
        self.offset += size
        return result

    def integer(self):
        width = int.from_bytes(self.take(2), 'little')
        if not 1 <= width <= 256:
            raise ValueError('Invalid integer width')
        data = self.take(width)
        if width > 1 and data[-1] == 0:
            raise ValueError('Nonminimal integer')
        return int.from_bytes(data, 'little')

    def finish(self):
        if self.offset != len(self.data):
            raise ValueError('Surplus record bytes')


class NodeCodec:
    """Frame: CB/version:u8/kind:u8/tag:u8/width:u16/body/crc32:u32.

    Branch body: critical_bit:u32, left:u64, right:u64. Leaf body: fixed key,
    value_length:u32, value. SUM appends a minimal unsigned aggregate. MAX
    appends sign:u8, unsigned magnitude, position:<QIH>, winner key. Ordinary
    maps append no augmentation. CRC detects damage, not adversarial authenticity.
    """

    def __init__(self, kind: Kind, key_bytes: int):
        if kind not in KINDS or not 1 <= key_bytes <= 65535:
            raise ValueError('Invalid node schema')
        self.kind, self.key_bytes = kind, key_bytes

    def encode(self, node):
        tag = 0 if isinstance(node, Leaf) else 1
        if isinstance(node, Leaf):
            key, value = _bytes(node.key), _bytes(node.value)
            if len(key) != self.key_bytes:
                raise ValueError('Wrong key width')
            body = key + struct.pack('<I', len(value)) + value
        elif isinstance(node, Branch):
            if not 0 <= node.bit < self.key_bytes * 8 or node.left <= 0 or node.right <= 0:
                raise ValueError('Invalid branch')
            body = struct.pack('<IQQ', node.bit, node.left, node.right)
        else:
            raise TypeError('Unknown node')
        if self.kind == Kind.MAP:
            if node.summary is not None:
                raise ValueError('Map node cannot have augmentation')
        elif self.kind == Kind.SUM:
            body += _uint(node.summary)
        else:
            rank = node.summary
            if not isinstance(rank, ExecutiveRank) or len(rank.key) != self.key_bytes:
                raise ValueError('Invalid maximum summary')
            if isinstance(node, Leaf) and rank.key != node.key:
                raise ValueError('Leaf winner must be its own key')
            body += bytes([int(rank.balance < 0)]) + _uint(abs(rank.balance))
            body += struct.pack('<QIH', *rank.updated) + _bytes(rank.key)
        data = b'CB' + struct.pack('<BBBH', 1, KINDS.index(self.kind), tag, self.key_bytes) + body
        if len(data) + 4 > MAX_RECORD:
            raise ValueError('Node too large')
        return data + struct.pack('<I', zlib.crc32(data))

    def decode(self, data):
        data = _bytes(data)
        if not 11 <= len(data) <= MAX_RECORD or zlib.crc32(data[:-4]) != int.from_bytes(data[-4:], 'little'):
            raise ValueError('Invalid node checksum/length')
        reader = _Reader(data[:-4])
        if reader.take(2) != b'CB':
            raise ValueError('Invalid node magic')
        version, kind, tag, width = struct.unpack('<BBBH', reader.take(5))
        if (version, kind, width) != (1, KINDS.index(self.kind), self.key_bytes) or tag not in (0, 1):
            raise ValueError('Wrong node schema')
        if tag == 0:
            key = reader.take(width)
            value = reader.take(int.from_bytes(reader.take(4), 'little'))
        else:
            bit, left, right = struct.unpack('<IQQ', reader.take(20))
        summary = None
        if self.kind == Kind.SUM:
            summary = reader.integer()
        elif self.kind == Kind.MAX:
            sign = reader.take(1)[0]
            magnitude = reader.integer()
            if sign > 1 or (sign and not magnitude):
                raise ValueError('Invalid signed balance')
            position = struct.unpack('<QIH', reader.take(14))
            summary = ExecutiveRank(-magnitude if sign else magnitude, position, reader.take(width))
        reader.finish()
        node = Leaf(key, value, summary) if tag == 0 else Branch(bit, left, right, summary)
        if self.encode(node) != data:
            raise ValueError('Noncanonical node')
        return node


@dataclass(frozen=True)
class TreeSchema:
    kind: Kind
    key_bytes: int
    value_type: str | None = None

    def encode_key(self, value) -> bytes:
        if self.kind == Kind.SUM and type(value) is int:
            data = value.to_bytes(self.key_bytes, 'big')
        else:
            data = _bytes(value.encode() if hasattr(value, 'encode') else value)
        if len(data) != self.key_bytes:
            raise ValueError('Wrong key width')
        return data

    def encode_value(self, value) -> bytes:
        """Domain objects delegate to block.py; opaque values are owned bytes."""
        if self.value_type == 'TransactionPosition':
            return transaction_position(*value)
        if self.value_type is None:
            return _bytes(value)
        from arka import block
        if not isinstance(value, getattr(block, self.value_type)):
            raise TypeError('Wrong block value type')
        return self.decode_value(value.encode()).encode()

    def decode_value(self, encoded):
        data = _bytes(encoded)
        if self.value_type == 'TransactionPosition':
            if len(data) != 12:
                raise ValueError('Invalid transaction position length')
            return struct.unpack('<QI', data)
        if self.value_type is None:
            return data
        from arka import block
        value = getattr(block, self.value_type).decode(data)
        if value.encode() != data:
            raise ValueError('Noncanonical or surplus domain value bytes')
        return value


SCHEMAS = {
    'executive_definitions': TreeSchema(Kind.MAP, 16, 'ExecutiveDefinition'),
    'asset_definitions': TreeSchema(Kind.MAP, 16, 'AssetDefinition'),
    'arka_utxos': TreeSchema(Kind.MAP, 14, 'ArkaUTXO'),
    'asset_utxos': TreeSchema(Kind.MAP, 14, 'AssetUTXO'),
    'tx_refs': TreeSchema(Kind.MAP, 32, 'TransactionPosition'),
    'executive_votes': TreeSchema(Kind.MAX, 16),
    **{name: TreeSchema(kind, 15) for name, kind in TREE_KINDS.items() if kind == Kind.SUM},
}


def proposal_key(value: int) -> bytes:
    return value.to_bytes(15, 'big')


def transaction_position(block_id: int, transaction_id: int) -> bytes:
    """tx_refs values; insert only when the transaction has hash_ref=True."""
    return struct.pack('<QI', block_id, transaction_id)


class MappedNodeStore:
    """Append allocator with bounded LRU mapping windows and owned decoded values.

    File header: immutable identity/schema plus CRC, then two checksummed
    (generation, allocated_tail) slots. Records: length:u32, NodeCodec bytes,
    zero alignment padding. The append interval is the allocation tracker;
    all records below the checkpoint tail remain allocated, including garbage.
    No per-node Python allocation index is built on reopen.
    """

    def __init__(self, path, schema: TreeSchema, windows=4):
        if windows < 1:
            raise ValueError('At least one mapping window is required')
        self.path, self.schema = Path(path), schema
        self.codec = NodeCodec(schema.kind, schema.key_bytes)
        self.windows, self.maps = windows, OrderedDict()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.file = self.path.open('r+b' if self.path.exists() else 'w+b', buffering=0)
        try:
            if os.fstat(self.file.fileno()).st_size == 0:
                self.file_id = uuid.uuid4().bytes
                header = b'ACBT' + struct.pack('<BBH', 1, KINDS.index(schema.kind), schema.key_bytes) + self.file_id
                _write(self.file, header + struct.pack('<I', zlib.crc32(header)))
                self.file.truncate(WINDOW)
                self.generation, self.tail = 0, HEADER_SIZE
                self.flush()
            else:
                header = self.file.read(28)
                expected = b'ACBT' + struct.pack('<BBH', 1, KINDS.index(schema.kind), schema.key_bytes)
                if len(header) != 28 or header[:8] != expected or zlib.crc32(header[:24]) != int.from_bytes(header[24:], 'little'):
                    raise ValueError('Invalid tree header')
                self.file_id = header[8:24]
                checkpoints = []
                for slot in (64, 96):
                    self.file.seek(slot)
                    record = self.file.read(20)
                    if len(record) == 20 and zlib.crc32(record[:16]) == int.from_bytes(record[16:], 'little'):
                        generation, tail = struct.unpack('<QQ', record[:16])
                        if HEADER_SIZE <= tail <= os.fstat(self.file.fileno()).st_size:
                            checkpoints.append((generation, tail))
                if not checkpoints:
                    raise ValueError('No valid allocation checkpoint')
                self.generation, self.tail = max(checkpoints)
        except BaseException:
            self.close()
            raise

    def _window(self, base):
        if base not in self.maps:
            if len(self.maps) == self.windows:
                _, old = self.maps.popitem(last=False)
                old.flush()
                old.close()
            self.maps[base] = mmap.mmap(self.file.fileno(), WINDOW, offset=base)
        self.maps.move_to_end(base)
        return self.maps[base]

    def _access(self, offset, size, data=None):
        result = bytearray() if data is None else None
        done = 0
        while done < size:
            base = (offset // WINDOW) * WINDOW
            start = offset - base
            count = min(size - done, WINDOW - start)
            window = self._window(base)
            if data is None:
                result.extend(window[start:start + count])
            else:
                window[start:start + count] = data[done:done + count]
            offset += count
            done += count
        return bytes(result) if result is not None else None

    def read(self, offset):
        if offset < HEADER_SIZE or offset % 8 or offset + 4 > self.tail:
            raise ValueError('Invalid node offset')
        size = int.from_bytes(self._access(offset, 4), 'little')
        if not 11 <= size <= MAX_RECORD or size > self.tail - offset - 4:
            raise ValueError('Invalid node extent')
        node = self.codec.decode(self._access(offset + 4, size))
        if isinstance(node, Branch) and any(child >= offset or child < HEADER_SIZE or child % 8
                                            for child in (node.left, node.right)):
            raise ValueError('Invalid child offset or cyclic node')
        return node

    def allocate(self, node):
        data = self.codec.encode(node)
        offset = self.tail
        if isinstance(node, Branch) and any(child >= offset or child < HEADER_SIZE or child % 8
                                            for child in (node.left, node.right)):
            raise ValueError('Children must already be allocated')
        end = (offset + 4 + len(data) + 7) & ~7
        if end > os.fstat(self.file.fileno()).st_size:
            for window in self.maps.values():
                window.flush()
                window.close()
            self.maps.clear()
            self.file.truncate(((end + WINDOW - 1) // WINDOW) * WINDOW)
        frame = struct.pack('<I', len(data)) + data
        self._access(offset, len(frame), frame)
        self.tail = end
        return offset

    def flush(self):
        for window in self.maps.values():
            window.flush()
        os.fsync(self.file.fileno())
        self.generation += 1
        record = struct.pack('<QQ', self.generation, self.tail)
        self.file.seek(64 + (self.generation % 2) * 32)
        _write(self.file, record + struct.pack('<I', zlib.crc32(record)))
        os.fsync(self.file.fileno())

    def close(self):
        for window in self.maps.values():
            window.close()
        self.maps.clear()
        self.file.close()


@dataclass(frozen=True)
class Patch:
    tree: str
    items: tuple[tuple[bytes, bytes | Update], ...] = ()
    remove: tuple[bytes, ...] = ()

    def __post_init__(self):
        items = []
        for key, value in self.items:
            if isinstance(value, Update):
                value = Update(_bytes(value.value), value.weight, value.balance,
                               None if value.updated is None else tuple(value.updated))
            else:
                value = _bytes(value)
            items.append((_bytes(key), value))
        object.__setattr__(self, 'items', tuple(items))
        object.__setattr__(self, 'remove', tuple(_bytes(key) for key in self.remove))


class Database:
    """Synchronous owning-thread backend; Coordinator supplies the async queue.

    A lifetime OS lock excludes other Database owners of this directory. A durable
    retry-ID index is not implemented.
    Retry uses expected_generation and inspects roots after uncertain outcomes.
    """

    def __init__(self, home='~/.arka/db', schemas=None):
        self.home = Path(home).expanduser()
        self.schemas = dict(SCHEMAS if schemas is None else schemas)
        self.stores, self.roots, self.generation = {}, {}, 0
        self.failed = False
        self.home.mkdir(parents=True, exist_ok=True)
        self.lock = None
        try:
            self.lock = (self.home / 'writer.lock').open('a+b')
            if os.name == 'nt':
                import msvcrt
                self.lock.seek(0)
                if not self.lock.read(1):
                    self.lock.write(b'\0')
                    self.lock.flush()
                self.lock.seek(0)
                msvcrt.locking(self.lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            for name, schema in self.schemas.items():
                if not name or any(c not in 'abcdefghijklmnopqrstuvwxyz_0123456789' for c in name):
                    raise ValueError('Invalid tree name')
                self.stores[name] = MappedNodeStore(self.home / (name + '.bin'), schema)
                self.roots[name] = 0
            self.journal = (self.home / 'manifest.bin').open('a+b', buffering=0)
            self._recover()
            if os.name != 'nt':
                fd = os.open(self.home, os.O_RDONLY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        except BaseException:
            self.close()
            raise

    def _recover(self):
        self.journal.seek(0)
        valid_end = 0
        while True:
            prefix = self.journal.read(4)
            if not prefix:
                break
            if len(prefix) != 4:
                break
            size = int.from_bytes(prefix, 'little')
            if not 1 <= size <= MAX_RECORD:
                raise ValueError('Corrupt manifest length')
            data = self.journal.read(size)
            crc = self.journal.read(4)
            if len(data) != size or len(crc) != 4:
                break
            if zlib.crc32(data) != int.from_bytes(crc, 'little'):
                raise ValueError('Corrupt manifest checksum')
            record = json.loads(data)
            if record['version'] != 1 or record['generation'] != self.generation + 1 or set(record['files']) != set(self.stores):
                raise ValueError('Invalid manifest generation/schema')
            roots = {}
            for name, (identity, tail, root) in record['files'].items():
                store = self.stores[name]
                if identity != store.file_id.hex() or not HEADER_SIZE <= tail <= store.tail or root < 0 or (root and root >= tail):
                    raise ValueError('Manifest references unavailable tree state')
                if root:
                    store.read(root)
                roots[name] = root
            self.roots, self.generation = roots, record['generation']
            valid_end = self.journal.tell()
        self.journal.truncate(valid_end)
        os.fsync(self.journal.fileno())

    def get(self, tree, key):
        return Critbit(self.stores[tree], self.schemas[tree].kind,
                       self.schemas[tree].key_bytes).get(self.roots[tree], key)

    def commit(self, patches, expected_generation, block_hash: bytes):
        if self.failed:
            raise RuntimeError('Uncertain commit outcome; close and recover before continuing')
        if expected_generation != self.generation:
            raise ValueError('Stale generation')
        block_hash = _bytes(block_hash)
        if len(block_hash) != 32:
            raise ValueError('Expected block hash')
        roots = dict(self.roots)
        seen = set()
        for patch in patches:
            if patch.tree in seen:
                raise ValueError('One combined patch per tree is required')
            seen.add(patch.tree)
            schema, store = self.schemas[patch.tree], self.stores[patch.tree]
            for _, value in patch.items:
                schema.decode_value(value.value if isinstance(value, Update) else value)
            roots[patch.tree] = Critbit(store, schema.kind, schema.key_bytes).update(
                roots[patch.tree], patch.items, remove=patch.remove)
        try:
            for store in self.stores.values():
                store.flush()
            record = {'version': 1, 'generation': self.generation + 1,
                      'block_hash': block_hash.hex(), 'files': {
                          name: [store.file_id.hex(), store.tail, roots[name]]
                          for name, store in self.stores.items()}}
            data = json.dumps(record, sort_keys=True, separators=(',', ':')).encode('ascii')
            if len(data) > MAX_RECORD:
                raise ValueError('Manifest too large')
            _write(self.journal, struct.pack('<I', len(data)) + data + struct.pack('<I', zlib.crc32(data)))
            os.fsync(self.journal.fileno())
        except BaseException:
            self.failed = True
            raise
        self.roots, self.generation = roots, self.generation + 1
        return self.generation

    def close(self):
        for store in self.stores.values():
            store.close()
        self.stores.clear()
        if hasattr(self, 'journal'):
            self.journal.close()
        if self.lock is not None:
            self.lock.close()


@dataclass(frozen=True)
class Request:
    id: str
    patches: tuple[Patch, ...] = ()
    expected_generation: int = 0
    block_hash: bytes = bytes(32)
    stop: bool = False

    def __post_init__(self):
        object.__setattr__(self, 'patches', tuple(self.patches))
        object.__setattr__(self, 'block_hash', _bytes(self.block_hash))


@dataclass(frozen=True)
class Response:
    id: str
    generation: int | None = None
    error: str | None = None


class Coordinator:
    """Commit validated block patches on one executor; reply after durability.

    Parsing/consensus and broker journaling remain outside this layer. There is
    no event outbox yet. A lost response can follow a successful commit; recover
    and inspect generation rather than assuming cancellation undoes disk work.
    """

    def __init__(self, requests, responses, home='~/.arka/db', schemas=None):
        self.requests, self.responses = requests, responses
        self.home, self.schemas = home, schemas
        self._running = False

    async def serve(self):
        if self._running:
            raise RuntimeError('Already serving')
        self._running = True
        executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='arka-db')
        loop = asyncio.get_running_loop()
        database = None

        async def call(function, *args):
            future = loop.run_in_executor(executor, function, *args)
            try:
                return await asyncio.shield(future)
            except asyncio.CancelledError:
                while not future.done():
                    try:
                        await asyncio.shield(future)
                    except asyncio.CancelledError:
                        pass
                future.result()
                raise

        try:
            # Assignment happens in the owning thread even if open is cancelled.
            def open_database():
                nonlocal database
                database = Database(self.home, self.schemas)
            await call(open_database)
            while True:
                request = await self.requests.get()
                try:
                    if request.stop:
                        await self.responses.put(Response(request.id, database.generation))
                        return
                    try:
                        generation = await call(database.commit, request.patches,
                                                request.expected_generation, request.block_hash)
                        response = Response(request.id, generation)
                    except Exception as exc:
                        response = Response(request.id, error=f'{type(exc).__name__}: {exc}')
                    await self.responses.put(response)
                finally:
                    self.requests.task_done()
        finally:
            if database is not None:
                await call(database.close)
            executor.shutdown(wait=False)
            self._running = False
