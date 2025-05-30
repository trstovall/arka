
from arka import block
import json


# ARKATEKT is the first executive of the ARKA network.

ARKATEKT = block.Nonce_16(bytes.fromhex((
    '0000_0000_0000_0000_0000_0000_0000_0000'
).replace('_', '')))


ARKATEKT_SIGNER = block.SignerKey(bytes.fromhex((
    '0000_0000_0000_0000_0000_0000_0000_0000'
    '0000_0000_0000_0000_0000_0000_0000_0000'
).replace('_', '')))


ARKATEKT_HASH = block.SignerHash(bytes.fromhex((
    '0000_0000_0000_0000_0000_0000_0000_0000'
    '0000_0000_0000_0000_0000_0000_0000_0000'
).replace('_', '')))


# ARKATEKT_SHARES is the first asset of the ARKA network,
# representing shares in Arkatekt, Inc.

ARKATEKT_SHARES = block.Nonce_16(bytes.fromhex((
    '0000_0000_0000_0000_0000_0000_0000_0000'
).replace('_', '')))


ARKATEKT_SHARES_SIGNER = block.SignerKey(bytes.fromhex((
    '0000_0000_0000_0000_0000_0000_0000_0000'
    '0000_0000_0000_0000_0000_0000_0000_0000'
).replace('_', '')))


ARKATEKT_SHARES_HASH = block.SignerHash(bytes.fromhex((
    '0000_0000_0000_0000_0000_0000_0000_0000'
    '0000_0000_0000_0000_0000_0000_0000_0000'
).replace('_', '')))


# ARKATEKT_CASH is the first cash asset of the ARKA network,
# representing USD holdings of Arkatekt, Inc.

ARKATEKT_CASH = block.Nonce_16(bytes.fromhex((
    '0000_0000_0000_0000_0000_0000_0000_0000'
).replace('_', '')))


ARKATEKT_CASH_SIGNER = block.SignerKey(bytes.fromhex((
    '0000_0000_0000_0000_0000_0000_0000_0000'
    '0000_0000_0000_0000_0000_0000_0000_0000'
).replace('_', '')))


ARKATEKT_CASH_HASH = block.SignerHash(bytes.fromhex((
    '0000_0000_0000_0000_0000_0000_0000_0000'
    '0000_0000_0000_0000_0000_0000_0000_0000'
).replace('_', '')))


# TRSTOVALL is the first publisher of the ARKA network,
# representing the creator of the ARKA network.

TRSTOVALL = block.SignerKey(bytes.fromhex((
    '0000_0000_0000_0000_0000_0000_0000_0000'
    '0000_0000_0000_0000_0000_0000_0000_0000'
).replace('_', '')))


TRSTOVALL_HASH = block.SignerHash(bytes.fromhex((
    '0000_0000_0000_0000_0000_0000_0000_0000'
    '0000_0000_0000_0000_0000_0000_0000_0000'
).replace('_', '')))


# JOHN is the first purchaser of ARKA,
# trading 100.00 USD for 1_000_000.000_000 ARKA shares.

JOHN = block.SignerKey(bytes.fromhex((
    '0000_0000_0000_0000_0000_0000_0000_0000'
    '0000_0000_0000_0000_0000_0000_0000_0000'
).replace('_', '')))


JOHN_HASH = block.SignerHash(bytes.fromhex((
    '0000_0000_0000_0000_0000_0000_0000_0000'
    '0000_0000_0000_0000_0000_0000_0000_0000'
).replace('_', '')))


# GENESIS is the first block of the ARKA network,
# containing the initial state of the network.

GENESIS = block.Block(
    header=block.BlockHeader(
        id=0,
        timestamp=0,
        prev_block=block.BlockHash(bytes(32)),
        publisher=TRSTOVALL_HASH,
        ntxs=1,
        root_hash=block.TransactionListHash(bytes.fromhex((
            '0000_0000_0000_0000_0000_0000_0000_0000'
            '0000_0000_0000_0000_0000_0000_0000_0000'
        ).replace('_', ''))),
        parameters=block.Parameters(
            target=128 * 2 ** 16,
            block_reward=100_000 * 10 ** 6,
            exec_fund=10_000_000_000 * 10 ** 6,
            utxo_fee=2**64 // (1_000 * 60 * 24 * 365),
            data_fee=100_000,
            executive=ARKATEKT
        ),
        nonce=block.Nonce(bytes(32))
    ),
    transactions=[
        block.Transaction(
            inputs=[
                # Spawn ARKATEKT
                block.ExecutiveSpawn(
                    executive=ARKATEKT,
                    signer=ARKATEKT_SIGNER,
                    memo=b'dict:' + json.dumps({
                        'name': 'Arkatekt, Inc.',
                        'repo': 'https://github.com/arkatekt/',
                        'dns': 'arkatekt.com',
                        'msg': 'An ARKA treasury company.',
                    }, indent=None, sort_keys=True).encode()
                ),
                # Spawn AKT
                block.AssetSpawn(
                    asset=ARKATEKT_SHARES,
                    signer=ARKATEKT_SHARES_SIGNER,
                    memo=b'dict:' + json.dumps({
                        'name': 'Arkatekt, Inc.',
                        'symbol': 'AKT',
                        'authorized': '1_000_000_000_000.000_000',
                        'outstanding': '500_000_000_000.000_000',
                        'msg': "Used to represent Arkatekt's shares.",
                    }, indent=None, sort_keys=True).encode(),
                    lock=True
                ),
                # Spawn AUSD
                block.AssetSpawn(
                    asset=ARKATEKT_CASH,
                    signer=ARKATEKT_CASH_SIGNER,
                    memo=b'dict:' + json.dumps({
                        'name': 'ArkatektUSD',
                        'symbol': 'AUSD',
                        'outstanding': '100.000_000',
                        'msg': "Used to represent Arkatekt's USD holdings.",
                    }, indent=None, sort_keys=True).encode(),
                    lock=False
                ),
                # Claim Executive Fund for creating the network
                block.ExecutiveSpend(
                    block=0,
                    signer=ARKATEKT_SIGNER,
                    memo=b'dict:' + json.dumps({
                        'msg': 'Claiming 10_000_000_000 ARKA shares.'
                    }, indent=None, sort_keys=True).encode()
                ),
                # Claim Block Reward for GENESIS block
                block.PublisherSpend(
                    block=0,
                    signer=TRSTOVALL,
                    memo=b'dict:' + json.dumps({
                        'msg': 'For transaction fees.'
                    }, indent=None, sort_keys=True).encode()
                ),
            ],
            outputs=[
                # ARKA shares to ARKATEKT
                block.ArkaUTXO(
                    signer=ARKATEKT_HASH,
                    units=5_000_000_000 * 10 ** 6,
                    memo=b'dict:' + json.dumps({
                        'msg': 'ARKA shares reserved by ARKATEKT.'
                    }, indent=None, sort_keys=True).encode(),
                ),
                # ARKATEKT shares to ARKATEKT
                block.AssetUTXO(
                    asset=ARKATEKT_SHARES,
                    signer=ARKATEKT_HASH,
                    units=500_000_000_000 * 10 ** 6,
                    memo=b'dict:' + json.dumps({
                        'msg': 'Arkatekt, Inc. treasury shares reserved by ARKATEKT.'
                    }, indent=None, sort_keys=True).encode(),
                ),
                # ARKA shares to TRSTOVALL
                block.ArkaUTXO(
                    signer=TRSTOVALL_HASH,
                    units=1_000_000_000 * 10 ** 6,
                    target=128 * 2 ** 16,
                    block_reward=100_000 * 10 ** 6,
                    exec_fund=0,
                    utxo_fee=2**64 // (1_000 * 60 * 24 * 365),
                    data_fee=100_000,
                    memo=b'dict:' + json.dumps({
                        'msg': 'ARKA shares paid to TRSTOVALL.'
                    }, indent=None, sort_keys=True).encode(),
                ),
                # ARKA shares to TRSTOVALL
                block.ArkaUTXO(
                    signer=TRSTOVALL_HASH,
                    units=4_000_000_000 * 10 ** 6,
                    memo=b'dict:' + json.dumps({
                        'msg': 'ARKA shares paid to TRSTOVALL.'
                    }, indent=None, sort_keys=True).encode(),
                ),
                # ARKATEKT shares to TRSTOVALL
                block.AssetUTXO(
                    asset=ARKATEKT_SHARES,
                    signer=TRSTOVALL_HASH,
                    units=500_000_000_000 * 10 ** 6,
                    memo=b'dict:' + json.dumps({
                        'msg': 'Arkatekt, Inc. treasury shares paid to TRSTOVALL.'
                    }, indent=None, sort_keys=True).encode(),
                ),
                # ArkatektUSD to JOHN
                block.AssetUTXO(
                    asset=ARKATEKT_CASH,
                    signer=JOHN_HASH,
                    units=100 * 10 ** 6,
                    memo=b'dict:' + json.dumps({
                        'msg': 'ArkatektUSD paid to JOHN.'
                    }, indent=None, sort_keys=True).encode(),
                ),
                # Burn the remaining ARKA to vote for ARKATEKT.
                block.ExecutiveVote(
                    executive=ARKATEKT,
                    promote=True,
                    units=100_000 * 10 ** 6,
                    memo=b'dict:' + json.dumps({
                        'msg': 'A vote for ARKATEKT.'
                    }, indent=None, sort_keys=True).encode(),
                ),
            ],
            signatures=[
                block.Signature(bytes.fromhex((
                    '0000_0000_0000_0000_0000_0000_0000_0000'
                    '0000_0000_0000_0000_0000_0000_0000_0000'
                    '0000_0000_0000_0000_0000_0000_0000_0000'
                    '0000_0000_0000_0000_0000_0000_0000_0000'
                ).replace('_', ''))),
                block.Signature(bytes.fromhex((
                    '0000_0000_0000_0000_0000_0000_0000_0000'
                    '0000_0000_0000_0000_0000_0000_0000_0000'
                    '0000_0000_0000_0000_0000_0000_0000_0000'
                    '0000_0000_0000_0000_0000_0000_0000_0000'
                ).replace('_', ''))),
                block.Signature(bytes.fromhex((
                    '0000_0000_0000_0000_0000_0000_0000_0000'
                    '0000_0000_0000_0000_0000_0000_0000_0000'
                    '0000_0000_0000_0000_0000_0000_0000_0000'
                    '0000_0000_0000_0000_0000_0000_0000_0000'
                ).replace('_', ''))),
                block.Signature(bytes.fromhex((
                    '0000_0000_0000_0000_0000_0000_0000_0000'
                    '0000_0000_0000_0000_0000_0000_0000_0000'
                    '0000_0000_0000_0000_0000_0000_0000_0000'
                    '0000_0000_0000_0000_0000_0000_0000_0000'
                ).replace('_', '')))
            ]
        )
    ]
)


GENESIS_HASH = block.BlockHash(bytes.fromhex((
    '0000_0000_0000_0000_0000_0000_0000_0000'
    '0000_0000_0000_0000_0000_0000_0000_0000'
).replace('_', '')))
