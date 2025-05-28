
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


GENESIS = block.Block(
    header=block.BlockHeader(
        id=0,
        timestamp=0,
        prev_block=block.BlockHash(bytes(32)),
        publisher=ARKATEKT_HASH,
        ntxs=1,
        root_hash=block.TransactionListHash(bytes.fromhex((
            '0000_0000_0000_0000_0000_0000_0000_0000'
            '0000_0000_0000_0000_0000_0000_0000_0000'
        ).replace('_', ''))),
        parameters=block.Parameters(
            target=128 * 2 ** 16,
            block_reward=100_000 * 10 ** 6,
            exec_fund=5_000_000_000 * 10 ** 6,
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
                    memo=json.dumps({
                        'name': 'Arkatekt, Inc.',
                        'repo': 'https://github.com/arkatekt/',
                        'dns': 'arkatekt.com',
                        'id': ARKATEKT_HASH.value.hex()
                    }, indent=None, sort_keys=True).encode()
                ),
                block.ExecutiveSpend(
                    block=0,
                    signer=ARKATEKT,
                    memo=json.dumps({
                        'msg': 'For Arkatekt, Inc. treasury.'
                    }, indent=None, sort_keys=True).encode()
                ),
                block.PublisherSpend(
                    block=0,
                    signer=ARKATEKT,
                    memo=json.dumps({
                        'msg': 'For Arkatekt, Inc. treasury.'
                    }, indent=None, sort_keys=True).encode()
                ),
                block.AssetSpawn(
                    signer=ARKATEKT,
                    memo=json.dumps({
                        'msg': (
                            'To represent Arkatekt Inc. shares: '
                            '(1_000_000_000_000 max authorized shares until lock expires).'
                        )
                    }, indent=None, sort_keys=True).encode(),
                    lock=True
                )
            ],
            outputs=[
                block.UTXOSpawn(
                    signer=ARKATEKT_HASH,
                    units=1_000_000_000 * 10 ** 6,
                    target=128 * 2 ** 16,
                    block_reward=100_000 * 10 ** 6,
                    exec_fund=0,
                    utxo_fee=2**64 // (1_000 * 60 * 24 * 365),
                    data_fee=100_000,
                    memo=json.dumps({
                        'msg': 'For liquidity.'
                    }, indent=None, sort_keys=True).encode(),
                ),
                block.UTXOSpawn(
                    signer=ARKATEKT_HASH,
                    units=10_000_000_000 * 10 ** 6,
                    memo=json.dumps({
                        'msg': 'For Arkatekt, Inc. treasury.'
                    }, indent=None, sort_keys=True).encode(),
                ),
                block.UTXOSpawn(
                    asset=ARKATEKT_HASH,
                    signer=ARKATEKT_HASH,
                    units=1_000_000_000_000 * 10 ** 6,
                    memo=json.dumps({
                        'msg': 'Arkatekt, Inc. treasury shares.'
                    }, indent=None, sort_keys=True).encode(),
                ),
                block.ExecutiveVote(
                    executive=ARKATEKT_HASH,
                    promote=True,
                    units=100_000 * 10 ** 6,
                    memo=json.dumps({
                        'msg': 'A vote FOR ARKA.'
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
                ).replace('_', '')))
            ]
        )
    ]
)
