
from arka import block
from os import urandom

import pytest

def test_parameters_serdes():
    x = block.Parameters(
        target = int.from_bytes(urandom(32), 'little'),
        block_reward = 100_000 * 10 ** 6,
        exec_fund = 0,
        utxo_fee = 2**64 // (1000 * 60 * 24 * 365),
        data_fee = 100_000,
        executive = urandom(32)
    )
    y = block.Parameters.decode(x.encode())
    assert x == y
    y = block.Parameters.decode(x.encode() + urandom(32))
    assert x == y


def test_signer_hash_serdes():
    x = block.SignerHash(urandom(32))
    y = block.SignerHash.decode(x.encode())
    assert x == y
    y = block.SignerHash.decode(x.encode() + urandom(32))
    assert x == y

def test_signer_key_serdes():
    x = block.SignerKey(urandom(32))
    y = block.SignerKey.decode(x.encode())
    assert x == y
    y = block.SignerKey.decode(x.encode() + urandom(32))
    assert x == y


@pytest.mark.asyncio
async def test_signer_key_hash():
    key = urandom(32)
    signer = block.SignerKey(key)
    hash = await signer.hash()
    assert isinstance(hash, block.SignerHash)
    assert isinstance(hash.hash, bytes)
    assert len(hash.hash) == 32


def test_signer_list_serdes():
    x = block.SignerList([
        block.SignerList([
            block.SignerKey(urandom(32)),
            block.SignerHash(urandom(32))
        ], 1),
        block.SignerHash(urandom(32)),
        block.SignerKey(urandom(32))
    ], 2)
    y = block.SignerList.decode(x.encode())
    assert x == y
    y = block.SignerList.decode(x.encode() + urandom(32))
    assert x == y


@pytest.mark.asyncio
async def test_signer_list_hash():
    keys = [block.SignerKey(urandom(32)) for i in range(6)]
    l1 = block.SignerList([
        keys[0], (await keys[1].hash()), keys[2],
        (await keys[3].hash()), keys[4], (await keys[5].hash())
    ], 3)
    l2 = block.SignerList([
        l1, (await keys[0].hash()), keys[1], (await keys[2].hash()),
        keys[3], (await keys[4].hash()), keys[5]
    ], 4)
    l3 = block.SignerList([
        (await l1.hash()), keys[0], (await keys[1].hash()), keys[2],
        (await keys[3].hash()), keys[4], keys[5]
    ], 4)
    x = await l2.hash()
    y = await l3.hash()
    assert x == y
    assert isinstance(x, block.SignerHash)
    assert len(x.hash) == 32


def test_utxo_ref_by_index_serdes():
    x = block.UTXORefByIndex(
        int.from_bytes(urandom(8), 'little'),
        int.from_bytes(urandom(4), 'little'),
        int.from_bytes(urandom(2), 'little')
    )
    y = block.UTXORefByIndex.decode(x.encode())
    assert x == y
    y = block.UTXORefByIndex.decode(x.encode() + urandom(32))
    assert x == y


def test_utxo_ref_by_hash_serdes():
    x = block.UTXORefByHash(
        urandom(32), int.from_bytes(urandom(2), 'little')
    )
    y = block.UTXORefByHash.decode(x.encode())
    assert x == y
    y = block.UTXORefByHash.decode(x.encode() + urandom(32))
    assert x == y


def test_utxo_spend_serdes():
    x = block.UTXOSpend(
        utxo=block.UTXORefByIndex(
            int.from_bytes(urandom(8), 'little'),
            int.from_bytes(urandom(4), 'little'),
            int.from_bytes(urandom(2), 'little')
        ),
        signer=block.SignerKey(urandom(32))
    )
    y = block.UTXOSpend.decode(x.encode())
    assert x == y
    x.utxo = block.UTXORefByHash(
        urandom(32), int.from_bytes(urandom(2), 'little')
    )
    y = block.UTXOSpend.decode(x.encode())
    assert x == y
    x.signer = block.SignerList([
        block.SignerKey(urandom(32)),
        block.SignerHash(urandom(32))
    ], 1)
    y = block.UTXOSpend.decode(x.encode())
    assert x == y
    x.signer = None
    y = block.UTXOSpend.decode(x.encode())
    assert x == y
    y = block.UTXOSpend.decode(x.encode() + urandom(32))
    assert x == y
    x.memo = urandom(0xff)
    y = block.UTXOSpend.decode(x.encode())
    assert x == y
    x.memo = urandom(0x100)
    y = block.UTXOSpend.decode(x.encode())
    assert x == y
    assert len(x.encode()) == x.size


def test_utxo_spend_signers():
    keys = [block.SignerKey(urandom(32)) for i in range(3)]
    x = block.UTXOSpend(
        block.UTXORefByHash(urandom(32), int.from_bytes(urandom(2), 'little')),
        keys[0]
    )
    assert x.signers == [keys[0].key]
    x.signer = block.SignerList(keys, 3)
    assert x.signers == [k.key for k in keys]
    x.signer = None
    with pytest.raises(ValueError):
        y = x.signers


def test_publisher_spend_serdes():
    x = block.PublisherSpend(
        block=int.from_bytes(urandom(8), 'little'),
        signer=block.SignerKey(urandom(32)),
        memo=urandom(32)
    )
    y = block.PublisherSpend.decode(x.encode())
    assert x == y
    x.signer = block.SignerList(
        [block.SignerKey(urandom(32)) for i in range(3)], 3
    )
    y = block.PublisherSpend.decode(x.encode())
    assert x == y
    x.signer = None
    y = block.PublisherSpend.decode(x.encode())
    assert x == y
    y = block.PublisherSpend.decode(x.encode() + urandom(32))
    assert x == y
    assert len(x.encode()) == x.size


def test_executive_spend_serdes():
    x = block.ExecutiveSpend(
        block=int.from_bytes(urandom(8), 'little'),
        signer=block.SignerKey(urandom(32)),
        memo=urandom(32)
    )
    y = block.ExecutiveSpend.decode(x.encode())
    assert x == y
    x.signer = block.SignerList(
        [block.SignerKey(urandom(32)) for i in range(3)], 3
    )
    y = block.ExecutiveSpend.decode(x.encode())
    assert x == y
    x.signer = None
    y = block.ExecutiveSpend.decode(x.encode())
    assert x == y
    y = block.ExecutiveSpend.decode(x.encode() + urandom(32))
    assert x == y
    assert len(x.encode()) == x.size


def test_executive_spawn_serdes():
    x = block.ExecutiveSpawn(
        signer=block.SignerKey(urandom(32)),
        memo=urandom(32)
    )
    y = block.ExecutiveSpawn.decode(x.encode())
    assert x == y
    x.signer = block.SignerList(
        [block.SignerKey(urandom(32)) for i in range(3)], 3
    )
    y = block.ExecutiveSpawn.decode(x.encode())
    assert x == y
    y = block.ExecutiveSpawn.decode(x.encode() + urandom(32))
    assert x == y


def test_asset_spawn_serdes():
    x = block.AssetSpawn(
        signer=block.SignerKey(urandom(32)),
        memo=urandom(32),
        lock=False
    )
    y = block.AssetSpawn.decode(x.encode())
    assert x == y
    x.signer = block.SignerList(
        [block.SignerKey(urandom(32)) for i in range(3)], 3
    )
    y = block.AssetSpawn.decode(x.encode())
    assert x == y
    x.lock = True
    y = block.AssetSpawn.decode(x.encode())
    assert x == y
    y = block.AssetSpawn.decode(x.encode() + urandom(32))
    assert x == y


def test_utxo_spawn_serdes():
    x = block.UTXOSpawn(
        signer=block.SignerHash(urandom(32)),
        units=int.from_bytes(urandom(8), 'little'),
        memo=urandom(32)
    )
    y = block.UTXOSpawn.decode(x.encode())
    assert x == y
    x.asset = block.SignerHash(urandom(32))
    y = block.UTXOSpawn.decode(x.encode())
    assert x == y
    x.signer = block.SignerKey(urandom(32))
    y = block.UTXOSpawn.decode(x.encode())
    assert x == y
    x.units = 0
    y = block.UTXOSpawn.decode(x.encode())
    assert x == y
    x.block_reward = int.from_bytes(urandom(8), 'little')
    y = block.UTXOSpawn.decode(x.encode())
    assert x == y
    x.exec_fund = int.from_bytes(urandom(8), 'little')
    y = block.UTXOSpawn.decode(x.encode())
    assert x == y
    x.utxo_fee = int.from_bytes(urandom(8), 'little')
    y = block.UTXOSpawn.decode(x.encode())
    assert x == y
    x.data_fee = int.from_bytes(urandom(8), 'little')
    y = block.UTXOSpawn.decode(x.encode())
    assert x == y
    y = block.UTXOSpawn.decode(x.encode() + urandom(32))
    assert x == y
    assert len(x.encode()) == x.size


def test_executive_vote_serdes():
    x = block.ExecutiveVote(
        executive=block.SignerHash(urandom(32))
    )
    y = block.ExecutiveVote.decode(x.encode())
    assert x == y
    x.units = int.from_bytes(urandom(8), 'little')
    y = block.ExecutiveVote.decode(x.encode())
    assert x == y
    x.memo = urandom(32)
    y = block.ExecutiveVote.decode(x.encode())
    assert x == y
    y = block.ExecutiveVote.decode(x.encode() + urandom(32))
    assert x == y
    assert len(x.encode()) == x.size

