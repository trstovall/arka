
from arka import block
from os import urandom

import pytest

def test_parameters_serdes():
    target = int.from_bytes(urandom(32), 'little')
    block_reward = 100_000 * 10 ** 6
    exec_fund = 0
    utxo_fee = 2**64 // (1000 * 60 * 24 * 365)
    data_fee = block_reward // 1_000_000
    executive = urandom(32)
    param_bytes = block.Parameters(
        target, block_reward, exec_fund,
        utxo_fee, data_fee, executive
    ).encode()
    params = block.Parameters.decode(param_bytes)
    assert params.size == len(param_bytes)
    assert .99 * target < params.target < 1.01 * target
    assert params.block_reward == block_reward
    assert params.exec_fund == exec_fund
    assert params.utxo_fee == utxo_fee
    assert params.data_fee == data_fee
    assert params.executive == executive
    params = block.Parameters.decode(param_bytes + urandom(32))
    assert params.size == len(param_bytes)


def test_signer_hash_serdes():
    hash = urandom(32)
    signer = block.SignerHash(hash)
    assert signer.hash == hash
    assert signer.encode() == hash
    assert block.SignerHash.decode(hash).hash == hash
    assert block.SignerHash.decode(hash + urandom(32)).hash == hash

def test_signer_key_serdes():
    key = urandom(32)
    signer = block.SignerKey(key)
    assert signer.key == key
    assert signer.encode() == key
    assert block.SignerKey.decode(key).key == key
    assert block.SignerKey.decode(key + urandom(32)).key == key


@pytest.mark.asyncio
async def test_signer_key_hash():
    key = urandom(32)
    signer = block.SignerKey(key)
    hash = await signer.hash()
    assert isinstance(hash, block.SignerHash)
    assert isinstance(hash.hash, bytes)
    assert len(hash.hash) == 32


def test_signer_list_serdes():
    s = block.SignerList([
        block.SignerList([
            block.SignerKey(urandom(32)),
            block.SignerHash(urandom(32))
        ], 1),
        block.SignerHash(urandom(32)),
        block.SignerKey(urandom(32))
    ], 2)
    ss = block.SignerList.decode(s.encode())
    assert s.threshold == ss.threshold
    assert s.keys == ss.keys
    assert len(s.keys) == 2
    assert isinstance(ss.signers[0], block.SignerList)
    assert ss.signers[0].threshold == s.signers[0].threshold
    assert ss.signers[0].keys == s.signers[0].keys
    assert len(ss.signers[0].keys) == 1
    assert isinstance(ss.signers[0].signers[0], block.SignerKey)
    assert ss.signers[0].signers[0].key == s.signers[0].signers[0].key
    assert isinstance(ss.signers[0].signers[1], block.SignerHash)
    assert ss.signers[0].signers[1].hash == s.signers[0].signers[1].hash
    assert isinstance(ss.signers[1], block.SignerHash)
    assert ss.signers[1].hash == s.signers[1].hash
    assert isinstance(ss.signers[2], block.SignerKey)
    assert ss.signers[2].key == s.signers[2].key


@pytest.mark.asyncio
async def test_signer_list_hash():
    s = block.SignerList([
        block.SignerList([
            block.SignerKey(urandom(32)),
            block.SignerHash(urandom(32))
        ], 1),
        block.SignerHash(urandom(32)),
        block.SignerKey(urandom(32))
    ], 2)
    ss = block.SignerList.decode(s.encode())
    assert (await s.hash()).hash == (await ss.hash()).hash
