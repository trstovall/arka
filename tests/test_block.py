
from arka import block
from os import urandom

import pytest

def test_parameters():
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


def test_spender_hash():
    hash = urandom(32)
    spender = block.SpenderHash(hash)
    assert spender.hash == hash
    assert spender.encode() == hash
    assert block.SpenderHash.decode(hash).hash == hash
    assert block.SpenderHash.decode(hash + urandom(32)).hash == hash

@pytest.mark.asyncio
async def test_spender_key():
    key = urandom(32)
    spender = block.SpenderKey(key)
    assert spender.key == key
    assert spender.encode() == key
    assert block.SpenderKey.decode(key).key == key
    assert block.SpenderKey.decode(key + urandom(32)).key == key
    hash = await spender.hash()
    assert isinstance(hash, block.SpenderHash)
    assert isinstance(hash.hash, bytes)
    assert len(hash.hash) == 32


@pytest.mark.asyncio
async def test_spender_list():
    pass

