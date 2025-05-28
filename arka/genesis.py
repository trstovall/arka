
from arka import block
import json


ARKATEKT = block.SignerList(
    signers=[
        block.SignerKey(bytes.fromhex((
            '0000_0000_0000_0000_0000_0000_0000_0000'
            '0000_0000_0000_0000_0000_0000_0000_0000'
        ).replace('_', ''))),
        block.SignerKey(bytes.fromhex((
            '0000_0000_0000_0000_0000_0000_0000_0000'
            '0000_0000_0000_0000_0000_0000_0000_0000'
        ).replace('_', ''))),
        block.SignerHash(bytes.fromhex((
            '0000_0000_0000_0000_0000_0000_0000_0000'
            '0000_0000_0000_0000_0000_0000_0000_0000'
        ).replace('_', ''))),
    ],
    threshold=2
)


ARKATEKT_HASH = block.SignerHash(bytes.fromhex((
    '0000_0000_0000_0000_0000_0000_0000_0000'
    '0000_0000_0000_0000_0000_0000_0000_0000'
).replace('_', '')))


ARKATEKT_SHARES = block.SignerList(
    signers=[
        block.SignerKey(bytes.fromhex((
            '0000_0000_0000_0000_0000_0000_0000_0000'
            '0000_0000_0000_0000_0000_0000_0000_0000'
        ).replace('_', ''))),
        block.SignerKey(bytes.fromhex((
            '0000_0000_0000_0000_0000_0000_0000_0000'
            '0000_0000_0000_0000_0000_0000_0000_0000'
        ).replace('_', ''))),
        block.SignerHash(bytes.fromhex((
            '0000_0000_0000_0000_0000_0000_0000_0000'
            '0000_0000_0000_0000_0000_0000_0000_0000'
        ).replace('_', ''))),
    ],
    threshold=2
)


ARKATEKT_SHARES_HASH = block.SignerHash(bytes.fromhex((
    '0000_0000_0000_0000_0000_0000_0000_0000'
    '0000_0000_0000_0000_0000_0000_0000_0000'
).replace('_', '')))


ARKATEKT_CASH = block.SignerList(
    signers=[
        block.SignerKey(bytes.fromhex((
            '0000_0000_0000_0000_0000_0000_0000_0000'
            '0000_0000_0000_0000_0000_0000_0000_0000'
        ).replace('_', ''))),
        block.SignerKey(bytes.fromhex((
            '0000_0000_0000_0000_0000_0000_0000_0000'
            '0000_0000_0000_0000_0000_0000_0000_0000'
        ).replace('_', ''))),
        block.SignerHash(bytes.fromhex((
            '0000_0000_0000_0000_0000_0000_0000_0000'
            '0000_0000_0000_0000_0000_0000_0000_0000'
        ).replace('_', ''))),
    ],
    threshold=2
)


ARKATEKT_CASH_HASH = block.SignerHash(bytes.fromhex((
    '0000_0000_0000_0000_0000_0000_0000_0000'
    '0000_0000_0000_0000_0000_0000_0000_0000'
).replace('_', '')))


TRSTOVALL = block.SignerList(
    signers=[
        block.SignerKey(bytes.fromhex((
            '0000_0000_0000_0000_0000_0000_0000_0000'
            '0000_0000_0000_0000_0000_0000_0000_0000'
        ).replace('_', ''))),
        block.SignerKey(bytes.fromhex((
            '0000_0000_0000_0000_0000_0000_0000_0000'
            '0000_0000_0000_0000_0000_0000_0000_0000'
        ).replace('_', ''))),
        block.SignerHash(bytes.fromhex((
            '0000_0000_0000_0000_0000_0000_0000_0000'
            '0000_0000_0000_0000_0000_0000_0000_0000'
        ).replace('_', ''))),
    ],
    threshold=2
)


TRSTOVALL_HASH = block.SignerHash(bytes.fromhex((
    '0000_0000_0000_0000_0000_0000_0000_0000'
    '0000_0000_0000_0000_0000_0000_0000_0000'
).replace('_', '')))


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
            executive=ARKATEKT_HASH
        ),
        nonce=block.Nonce(bytes(32))
    ),
    transactions=[
        block.Transaction(
            inputs=[
                block.ExecutiveSpawn(
                    signer=ARKATEKT,
                    memo=b'dict:' + json.dumps({
                        'id': ARKATEKT_HASH.value.hex(),
                        'name': 'Arkatekt, Inc.',
                        'repo': 'https://github.com/arkatekt/',
                        'dns': 'arkatekt.com',
                        'msg': 'An ARKA treasury.',
                    }, indent=None, sort_keys=True).encode()
                ),
                block.AssetSpawn(
                    signer=ARKATEKT_SHARES,
                    memo=b'dict:' + json.dumps({
                        'id': ARKATEKT_SHARES_HASH.value.hex(),
                        'name': 'Arkatekt, Inc.',
                        'symbol': 'AKT',
                        'authorized': '1_000_000_000_000.000_000',
                        'outstanding': '500_000_000_000.000_000',
                    }, indent=None, sort_keys=True).encode(),
                    lock=True
                ),
                block.AssetSpawn(
                    signer=ARKATEKT_CASH,
                    memo=b'dict:' + json.dumps({
                        'id': ARKATEKT_CASH_HASH.value.hex(),
                        'name': 'ArkatektUSD',
                        'symbol': 'AUSD',
                        'outstanding': '0.000_000',
                        'msg': "Used to represent Arkatekt's USD holdings.",
                    }, indent=None, sort_keys=True).encode(),
                    lock=False
                ),
                block.ExecutiveSpend(
                    block=0,
                    signer=ARKATEKT,
                    memo=b'dict:' + json.dumps({
                        'msg': 'Claiming 10_000_000_000 ARKA shares.'
                    }, indent=None, sort_keys=True).encode()
                ),
                block.PublisherSpend(
                    block=0,
                    signer=TRSTOVALL,
                    memo=b'dict:' + json.dumps({
                        'msg': 'For transaction fees.'
                    }, indent=None, sort_keys=True).encode()
                ),
            ],
            outputs=[
                # ARKATEKT
                block.UTXOSpawn(
                    signer=ARKATEKT_HASH,
                    units=5_000_000_000 * 10 ** 6,
                    memo=b'dict:' + json.dumps({
                        'msg': 'ARKA shares reserved by ARKATEKT.'
                    }, indent=None, sort_keys=True).encode(),
                ),
                block.UTXOSpawn(
                    asset=ARKATEKT_HASH,
                    signer=ARKATEKT_HASH,
                    units=500_000_000_000 * 10 ** 6,
                    memo=b'dict:' + json.dumps({
                        'msg': 'Arkatekt, Inc. treasury shares reserved by ARKATEKT.'
                    }, indent=None, sort_keys=True).encode(),
                ),
                # TRSTOVALL
                block.UTXOSpawn(
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
                block.UTXOSpawn(
                    signer=TRSTOVALL_HASH,
                    units=4_000_000_000 * 10 ** 6,
                    memo=b'dict:' + json.dumps({
                        'msg': 'ARKA shares paid to TRSTOVALL.'
                    }, indent=None, sort_keys=True).encode(),
                ),
                block.UTXOSpawn(
                    asset=ARKATEKT_HASH,
                    signer=TRSTOVALL_HASH,
                    units=500_000_000_000 * 10 ** 6,
                    memo=b'dict:' + json.dumps({
                        'msg': 'Arkatekt, Inc. treasury shares paid to TRSTOVALL.'
                    }, indent=None, sort_keys=True).encode(),
                ),
                # Burn the remaining ARKA to vote for ARKATEKT.
                block.ExecutiveVote(
                    executive=ARKATEKT_HASH,
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
