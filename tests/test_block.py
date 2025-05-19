
from arka import block
from os import urandom

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
