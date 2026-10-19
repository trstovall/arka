import asyncio

import pytest

from arka.critbit import Branch, Critbit, ExecutiveRank, Kind, Leaf, Update
from arka.db import (Coordinator, Database, MappedNodeStore, NodeCodec, Patch,
                     Request, SCHEMAS, TreeSchema)


def test_schema_key_and_position_codecs():
    schema = SCHEMAS['tx_refs']
    assert schema.decode_value(schema.encode_value((2**40, 31))) == (2**40, 31)
    with pytest.raises(ValueError):
        schema.decode_value(bytes(13))
    votes = SCHEMAS['block_reward']
    assert votes.encode_key(255) < votes.encode_key(256)


def test_block_value_adapter():
    from arka import block
    value = block.ArkaUTXO(signer=block.SignerHash(bytes(32)), units=100)
    schema = SCHEMAS['arka_utxos']
    data = schema.encode_value(value)
    assert data == value.encode()
    assert schema.decode_value(data).encode() == data
    with pytest.raises(ValueError):
        schema.decode_value(data + b'x')


@pytest.mark.parametrize('kind,summary', [
    (Kind.MAP, None), (Kind.SUM, 2**160),
    (Kind.MAX, ExecutiveRank(-12, (100, 3, 2), b'ab'))])
def test_node_codecs(kind, summary):
    codec = NodeCodec(kind, 2)
    for node in (Leaf(b'ab', b'payload', summary), Branch(9, 4096, 8192, summary)):
        encoded = codec.encode(node)
        assert codec.decode(memoryview(encoded)) == node
        for malformed in (encoded[:-1], encoded + b'x', b'x' + encoded[1:]):
            with pytest.raises(ValueError):
                codec.decode(malformed)


def test_store_window_boundary_reopen(tmp_path):
    path = tmp_path / 'map.bin'
    schema = TreeSchema(Kind.MAP, 1)
    store = MappedNodeStore(path, schema, windows=1)
    tree = Critbit(store, Kind.MAP, 1)
    try:
        root = tree.update(0, {b'a': b'a' * (9 * 1024 * 1024), b'b': b''})
        store.flush()
        assert len(store.maps) <= 1
    finally:
        store.close()
    store = MappedNodeStore(path, schema, windows=1)
    try:
        assert len(Critbit(store, Kind.MAP, 1).get(root, b'a')) == 9 * 1024 * 1024
        assert Critbit(store, Kind.MAP, 1).get(root, b'b') == b''
        with pytest.raises(ValueError):
            store.read(root + 1)
    finally:
        store.close()


def test_atomic_roots_recovery_and_writer_lock(tmp_path):
    schemas = {'map': TreeSchema(Kind.MAP, 1), 'sum': TreeSchema(Kind.SUM, 1)}
    db = Database(tmp_path, schemas)
    try:
        with pytest.raises(OSError):
            Database(tmp_path, schemas)
        assert db.commit((Patch('map', ((b'a', b'old'),)),
                          Patch('sum', ((b'a', Update(b'', weight=10)),))), 0, bytes(32)) == 1
        with pytest.raises(KeyError):
            db.commit((Patch('map', ((b'a', b'unpublished'),)),
                       Patch('sum', remove=(b'z',))), 1, bytes(32))
        assert db.get('map', b'a') == b'old'
    finally:
        db.close()
    with (tmp_path / 'manifest.bin').open('ab') as file:
        file.write(b'\x10\x00')  # Simulated incomplete final record.
    db = Database(tmp_path, schemas)
    try:
        assert db.generation == 1
        assert db.get('map', b'a') == b'old'
        assert db.commit((Patch('map', ((b'a', b'new'),)),), 1, bytes(32)) == 2
    finally:
        db.close()


def test_queue_commit_and_stop(tmp_path):
    async def scenario():
        requests, responses = asyncio.Queue(), asyncio.Queue()
        worker = Coordinator(requests, responses, tmp_path, {'map': TreeSchema(Kind.MAP, 1)})
        task = asyncio.create_task(worker.serve())
        await requests.put(Request('commit', (Patch('map', ((b'a', b'value'),)),)))
        reply = await responses.get()
        assert reply.generation == 1 and reply.error is None
        await requests.put(Request('stop', stop=True))
        assert (await responses.get()).id == 'stop'
        await task
    asyncio.run(scenario())


def test_defrag_to_mapped_replacement(tmp_path):
    schema = TreeSchema(Kind.MAP, 1)
    source = MappedNodeStore(tmp_path / 'source.bin', schema)
    destination = MappedNodeStore(tmp_path / 'replacement.bin', schema)
    try:
        tree = Critbit(source, Kind.MAP, 1)
        root = tree.update(0, {b'a': b'old', b'b': b'shared'})
        root = tree.update(root, {b'a': b'new'})
        copied = tree.defrag(root, destination)
        destination.flush()
        assert destination.tail < source.tail
    finally:
        source.close()
        destination.close()
    reopened = MappedNodeStore(tmp_path / 'replacement.bin', schema)
    try:
        tree = Critbit(reopened, Kind.MAP, 1)
        assert tree.get(copied, b'a') == b'new'
        assert tree.get(copied, b'b') == b'shared'
    finally:
        reopened.close()
