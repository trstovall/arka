
from arka import block
import json


# ARKATEKT is the first executive of the ARKA network.

ARKATEKT = block.Nonce_16(
    b'Arkatekt, Inc.' + bytes(2)
)

# For multisig, use block.SignerList

ARKATEKT_SIGNER = block.SignerKey(bytes.fromhex((
    '0000_0000_0000_0000_0000_0000_0000_0000'
    '0000_0000_0000_0000_0000_0000_0000_0000'
).replace('_', '')))


# ARKATEKT_SHARES is the first asset of the ARKA network,
# representing common stock shares of Arkatekt, Inc.

ARKATEKT_SHARES = ARKATEKT


# ARKATEKT_USD is the first USD "stablecoin" of the ARKA network,
# representing USD owed to customers of Arkatekt, Inc.

ARKATEKT_USD = block.Nonce_16(
    b'Arkatekt USD\x00\x00\x00\x00'
)


# TRSTOVALL is the first publisher of the ARKA network,
# representing the creator of the ARKA network.

TRSTOVALL = block.SignerKey(bytes.fromhex((
    '0000_0000_0000_0000_0000_0000_0000_0000'
    '0000_0000_0000_0000_0000_0000_0000_0000'
).replace('_', '')))


# JOHN is the first purchaser of ARKA,
# trading 1.00 USD for 1_000_000.000_000 ARKA shares.

JOHN = block.SignerKey(bytes.fromhex((
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
        publisher=TRSTOVALL,
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
        nonce=block.Nonce_32(bytes(32))
    ),
    transactions=[
        block.Transaction(
            inputs=[
                # Define ARKATEKT
                block.ExecutiveDefinition(
                    # signer is implicitly ARKATEKT_SIGNER
                    executive=ARKATEKT,
                    memo=b'json:' + json.dumps({
                        'name': 'Arkatekt, Inc.',
                        'repo': 'https://github.com/arkatekt/',
                        'dns': 'arkatekt.com',
                        'msg': 'An ARKA treasury company.',
                    }, indent=None, sort_keys=True).encode()
                ),
                # Define AKT (Arkatekt, Inc. shares)
                block.AssetDefinition(
                    asset=ARKATEKT_SHARES,
                    signer=ARKATEKT_SIGNER,
                    memo=b'json:' + json.dumps({
                        'name': 'Arkatekt, Inc.',
                        'symbol': 'AKT',
                        'authorized': '1_000_000_000_000.000_000',
                        'msg': "Arkatekt common stock.",
                    }, indent=None, sort_keys=True).encode(),
                    lock=True
                ),
                # Define AUSD (Arkatekt USD)
                block.AssetDefinition(
                    asset=ARKATEKT_USD,
                    signer=ARKATEKT_SIGNER,
                    memo=b'json:' + json.dumps({
                        'name': 'Arkatekt USD',
                        'symbol': 'AUSD',
                        'msg': "USD credit issued by Arkatekt, Inc.",
                    }, indent=None, sort_keys=True).encode(),
                    lock=False
                ),
                # Claim Executive Fund for creating the network
                block.ExecutiveSpend(
                    # signer is implicitly ARKATEKT_SIGNER
                    block=0,
                    memo=b'json:' + json.dumps({
                        'msg': 'Claiming 10_000_000_000 ARKA shares.'
                    }, indent=None, sort_keys=True).encode()
                ),
                # Claim Block Reward for GENESIS block
                block.PublisherSpend(
                    # signer is implicitly TRSTOVALL
                    block=0,
                    memo=b'json:' + json.dumps({
                        'msg': 'For transaction fees.'
                    }, indent=None, sort_keys=True).encode()
                ),
            ],
            outputs=[
                # ARKA retained by ARKATEKT
                block.ArkaUTXO(
                    signer=ARKATEKT_SIGNER,
                    units=5_000_000_000 * 10 ** 6,
                    memo=b'json:' + json.dumps({
                        'msg': '5 billion ARKA reserved by ARKATEKT.'
                    }, indent=None, sort_keys=True).encode(),
                ),
                # ARKATEKT common stock retained by ARKATEKT
                block.AssetUTXO(
                    asset=ARKATEKT_SHARES,
                    signer=ARKATEKT_SIGNER,
                    units=500_000_000_000 * 10 ** 6,
                    memo=b'json:' + json.dumps({
                        'msg': '500 billion Arkatekt, Inc. shares reserved by ARKATEKT.'
                    }, indent=None, sort_keys=True).encode(),
                ),
                # ARKA transferred to TRSTOVALL
                block.ArkaUTXO(
                    signer=TRSTOVALL,
                    units=1_000_000_000 * 10 ** 6,  # 1 billion ARKA shares
                    target=128 * 2 ** 16,
                    block_reward=100_000 * 10 ** 6, # 100k ARKA shares
                    exec_fund=0,                    # Set executive fund to zero
                    utxo_fee=2**64 // (1_000 * 60 * 24 * 365),  # UTXOs decay over 1,000 years
                    data_fee=100_000,               # 0.1 ARKA per byte of data
                    memo=b'json:' + json.dumps({
                        'msg': '1 billion ARKA paid to TRSTOVALL with votes set.'
                    }, indent=None, sort_keys=True).encode(),
                ),
                # ARKA transferred to TRSTOVALL
                block.ArkaUTXO(
                    signer=TRSTOVALL,
                    units=4_000_000_000 * 10 ** 6,
                    memo=b'json:' + json.dumps({
                        'msg': '4 billion ARKA paid to TRSTOVALL without votes set.'
                    }, indent=None, sort_keys=True).encode(),
                ),
                # ARKATEKT common stock transferred to TRSTOVALL
                block.AssetUTXO(
                    asset=ARKATEKT_SHARES,
                    signer=TRSTOVALL,
                    units=500_000_000_000 * 10 ** 6,
                    memo=b'json:' + json.dumps({
                        'msg': '500 billion Arkatekt, Inc. shares paid to TRSTOVALL.'
                    }, indent=None, sort_keys=True).encode(),
                ),
                # Arkatekt USD transferred to JOHN
                block.AssetUTXO(
                    asset=ARKATEKT_USD,
                    signer=JOHN,
                    units=1 * 10 ** 6,
                    memo=b'json:' + json.dumps({
                        'msg': '$1 AUSD paid to JOHN.'
                    }, indent=None, sort_keys=True).encode(),
                ),
                # Burn the remaining ARKA to vote for ARKATEKT.
                block.ExecutiveVote(
                    executive=ARKATEKT,
                    promote=True,                   # True = vote for, False = vote against
                    units=100_000 * 10 ** 6,        # ARKA burned to vote
                    memo=b'json:' + json.dumps({
                        'msg': 'A vote for ARKATEKT.'
                    }, indent=None, sort_keys=True).encode(),
                ),
            ],
            signatures=[
                # ARKATEKT_SIGNER signature
                block.Signature(bytes.fromhex((
                    '0000_0000_0000_0000_0000_0000_0000_0000'
                    '0000_0000_0000_0000_0000_0000_0000_0000'
                    '0000_0000_0000_0000_0000_0000_0000_0000'
                    '0000_0000_0000_0000_0000_0000_0000_0000'
                ).replace('_', ''))),
                # TRSTOVALL signature
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


# JOHN purchases 1_000_000.000_000 ARKA from ARKATEKT for $1 AUSD
TX_1 = block.Transaction(
    inputs=[
        # Spend $1 AUSD from JOHN's wallet
        # signer is implicitly JOHN
        block.UTXOSpend(
            utxo=block.UTXORefByIndex(
                block=0, tx=0, output=5
            )
        ),
        # Spend 1_000_000.000_000 ARKA from ARKATEKT's wallet
        # signer is implicitly ARKATEKT_SIGNER
        block.UTXOSpend(
            utxo=block.UTXORefByIndex(
                block=0, tx=0, output=0
            )
        )
    ],
    outputs=[
        # ARKA shares to JOHN
        block.ArkaUTXO(
            signer=JOHN,
            units=1_000_000 * 10 ** 6,  # 1 million ARKA shares
            memo=b'dict:' + json.dumps({
                'msg': '1 million ARKA shares purchased by JOHN.'
            }, indent=None, sort_keys=True).encode(),
        ),
        # Change back to ARKATEKT
        # (ARKATEKT pays for the transaction fee)
        block.ArkaUTXO(
            signer=ARKATEKT_SIGNER,
            units=999_000_000 * 10 ** 6,  # Remaining ARKA shares
            memo=b'dict:' + json.dumps({
                'msg': 'Change back to ARKATEKT.'
            }, indent=None, sort_keys=True).encode(),
        )
        # AUSD is destroyed in the transaction,
        # as it is credit ARKATEKT owes to itself.
    ],
    signatures=[
        # JOHN's signature for the AUSD spend
        block.Signature(bytes.fromhex((
            '0000_0000_0000_0000_0000_0000_0000_0000'
            '0000_0000_0000_0000_0000_0000_0000_0000'
            '0000_0000_0000_0000_0000_0000_0000_0000'
            '0000_0000_0000_0000_0000_0000_0000_0000'
        ).replace('_', ''))),
        # ARKATEKT_SIGNER's signature for the ARKA spend
        block.Signature(bytes.fromhex((
            '0000_0000_0000_0000_0000_0000_0000_0000'
            '0000_0000_0000_0000_0000_0000_0000_0000'
            '0000_0000_0000_0000_0000_0000_0000_0000'
            '0000_0000_0000_0000_0000_0000_0000_0000'
        ).replace('_', '')))
    ]
)
