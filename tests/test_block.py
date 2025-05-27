
from arka import block
from os import urandom

import pytest
from asyncio import gather


rand = lambda n: int.from_bytes(urandom(n), 'little')


def test_abstract_element():
    x = block.AbstractElement()
    with pytest.raises(NotImplementedError):
        x == block.AbstractElement()
    with pytest.raises(NotImplementedError):
        y = x.size
    with pytest.raises(NotImplementedError):
        y = x.encode()
    with pytest.raises(NotImplementedError):
        y = block.AbstractElement.decode(b'')


def test_bytes_serdes():
    class A(block.Bytes):
        SIZE = 10
    x = A(urandom(10))
    assert x.encode() == x.value
    y = A.decode(x.encode())
    assert x == y
    y = A.decode(x.encode() + urandom(32))
    assert x == y
    assert x.size == A.SIZE
    with pytest.raises(ValueError):
        x = A(urandom(9))
    with pytest.raises(ValueError):
        x = A(urandom(11))
    with pytest.raises(ValueError):
        x = A(list(urandom(10)))


def test_signer_hash_serdes():
    x = block.SignerHash(urandom(32))
    assert x.encode() == x.value
    y = block.SignerHash.decode(x.encode())
    assert x == y
    y = block.SignerHash.decode(x.encode() + urandom(32))
    assert x == y
    assert len(x.encode()) == x.size


def test_signer_key_serdes():
    x = block.SignerKey(urandom(32))
    assert x.encode() == x.value
    y = block.SignerKey.decode(x.encode())
    assert x == y
    y = block.SignerKey.decode(x.encode() + urandom(32))
    assert x == y
    assert len(x.encode()) == x.size


@pytest.mark.asyncio
async def test_signer_key_hash():
    key = urandom(32)
    signer = block.SignerKey(key)
    hash = await signer.hash()
    assert isinstance(hash, block.SignerHash)


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
    assert len(x.encode()) == x.size


@pytest.mark.asyncio
async def test_signer_list_keys():
    keys = [block.SignerKey(urandom(32)) for i in range(4)]
    hashes = await gather(*[k.hash() for k in keys])
    x = block.SignerList([
        block.SignerList([
            keys[0],
            hashes[1]
        ], 1),
        block.SignerList([
            keys[1],
            hashes[3],
            keys[2]
        ], 2),
        hashes[0],
        keys[3]
    ], 1)
    assert x.keys == keys


@pytest.mark.asyncio
async def test_signer_list_hash():
    keys = [block.SignerKey(urandom(32)) for i in range(6)]
    hashes = await gather(*[k.hash() for k in keys])
    l1 = block.SignerList([
        keys[0], hashes[1], keys[2],
        hashes[3], keys[4], hashes[5]
    ], 3)
    l2 = block.SignerList([
        l1, hashes[0], keys[1], hashes[2],
        keys[3], hashes[4], keys[5]
    ], 4)
    l3 = block.SignerList([
        (await l1.hash()), keys[0], hashes[1], keys[2],
        hashes[3], keys[4], keys[5]
    ], 4)
    x = await l2.hash()
    y = await l3.hash()
    assert x == y
    assert isinstance(x, block.SignerHash)


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
    assert len(x.encode()) == x.size


def test_utxo_ref_by_hash_serdes():
    x = block.UTXORefByHash(
        block.TransactionHash(urandom(32)),
        int.from_bytes(urandom(2), 'little')
    )
    y = block.UTXORefByHash.decode(x.encode())
    assert x == y
    y = block.UTXORefByHash.decode(x.encode() + urandom(32))
    assert x == y
    assert len(x.encode()) == x.size


def test_transaction_element_serdes():
    x = block.TransactionElement()
    mlen = x._encode_mlen(x.memo)
    assert mlen == b''
    assert x.memo == x._decode_memo(0, mlen + urandom(0x100))
    x = block.TransactionElement(urandom(0xff))
    mlen = x._encode_mlen(x.memo)
    assert mlen == b'\xff'
    assert x.memo == x._decode_memo(1, mlen + x.memo + urandom(0x100))
    x = block.TransactionElement(urandom(0x100))
    mlen = x._encode_mlen(x.memo)
    assert mlen == b'\x00\x01'
    assert x.memo == x._decode_memo(2, mlen + x.memo + urandom(0x100))
    with pytest.raises(ValueError):
        x = block.TransactionElement(b'')
    with pytest.raises(ValueError):
        x = block.TransactionElement(urandom(0x1_0000))
    with pytest.raises(ValueError):
        x = block.TransactionElement._decode_memo(1, b'\x00')
    with pytest.raises(ValueError):
        x = block.TransactionElement._decode_memo(
            3, b'\x00\x00\x01' + urandom(0x1_0000)
        )


def test_transaction_input_serdes():
    keys = [block.SignerKey(urandom(32)) for i in range(2)]
    x = block.TransactionInput(keys[0])
    assert x.signer == x._decode_signer(*x._encode_signer(x.signer))
    x = block.TransactionInput(block.SignerList(keys, 2))
    assert x.signer == x._decode_signer(*x._encode_signer(x.signer))
    with pytest.raises(ValueError):
        y = x._encode_signer(None)
    with pytest.raises(ValueError):
        y = x._decode_signer(*x._encode_optional_signer(None))    
    x = block.TransactionInput()
    assert x.signer == x._decode_optional_signer(
        *x._encode_optional_signer(None)
    )


def test_transaction_input_signers():
    keys = [block.SignerKey(urandom(32)) for i in range(2)]
    x = block.TransactionInput(keys[0])
    assert x.signers == keys[:1]
    x = block.TransactionInput(block.SignerList(keys, 2))
    assert x.signers == keys


def test_utxo_spend_serdes():
    x = block.UTXOSpend(
        block.UTXORefByIndex(
            int.from_bytes(urandom(8), 'little'),
            int.from_bytes(urandom(4), 'little'),
            int.from_bytes(urandom(2), 'little')
        )
    )
    y = block.UTXOSpend.decode(x.encode())
    assert x == y
    y = block.UTXOSpend.decode(x.encode() + urandom(32))
    assert x == y
    x = block.UTXOSpend(
        block.UTXORefByHash(
            block.TransactionHash(urandom(32)),
            int.from_bytes(urandom(2), 'little')
        )
    )
    y = block.UTXOSpend.decode(x.encode())
    assert x == y
    y = block.UTXOSpend.decode(x.encode() + urandom(32))
    assert x == y
    x = block.UTXOSpend(
        block.UTXORefByIndex(
            int.from_bytes(urandom(8), 'little'),
            int.from_bytes(urandom(4), 'little'),
            int.from_bytes(urandom(2), 'little')
        ),
        block.SignerList([block.SignerKey(urandom(32)) for i in range(2)], 2),
        urandom(0x100)
    )
    y = block.UTXOSpend.decode(x.encode())
    assert x == y
    y = block.UTXOSpend.decode(x.encode() + urandom(32))
    assert x == y
    assert len(x.encode()) == x.size


def test_utxo_spend_signers():
    keys = [block.SignerKey(urandom(32)) for i in range(3)]
    x = block.UTXOSpend(
        utxo=block.UTXORefByHash(
            block.TransactionHash(urandom(32)),
            rand(2)
        ),
        signer=keys[0]
    )
    assert x.signers == keys[:1]
    x.signer = block.SignerList(keys, 3)
    assert x.signers == keys
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
    x = block.PublisherSpend(
        block=int.from_bytes(urandom(8), 'little'),
        memo=urandom(32)
    )
    y = block.PublisherSpend.decode(x.encode())
    assert x == y
    y = block.PublisherSpend.decode(x.encode() + urandom(32))
    assert x == y
    assert len(x.encode()) == x.size


def test_publisher_spend_signers():
    keys = [block.SignerKey(urandom(32)) for i in range(3)]
    x = block.PublisherSpend(
        block=int.from_bytes(urandom(8), 'little'),
        signer=keys[0],
        memo=urandom(32)
    )
    assert x.signers == [keys[0]]
    x = block.PublisherSpend(
        block=int.from_bytes(urandom(8), 'little'),
        signer=block.SignerList(keys, 3),
        memo=urandom(32)
    )
    assert x.signers == keys
    x = block.PublisherSpend(
        block=int.from_bytes(urandom(8), 'little'),
        memo=urandom(32)
    )
    with pytest.raises(ValueError):
        y = x.signers


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
    x = block.ExecutiveSpend(
        block=int.from_bytes(urandom(8), 'little'),
        memo=urandom(32)
    )
    y = block.ExecutiveSpend.decode(x.encode())
    assert x == y
    y = block.ExecutiveSpend.decode(x.encode() + urandom(32))
    assert x == y
    assert len(x.encode()) == x.size


def test_executive_spend_signers():
    keys = [block.SignerKey(urandom(32)) for i in range(3)]
    x = block.ExecutiveSpend(
        block=int.from_bytes(urandom(8), 'little'),
        signer=keys[0],
        memo=urandom(32)
    )
    assert x.signers == [keys[0]]
    x = block.ExecutiveSpend(
        block=int.from_bytes(urandom(8), 'little'),
        signer=block.SignerList(keys, 3),
        memo=urandom(32)
    )
    assert x.signers == keys
    x = block.ExecutiveSpend(
        block=int.from_bytes(urandom(8), 'little'),
        memo=urandom(32)
    )
    with pytest.raises(ValueError):
        y = x.signers


def test_executive_spawn_serdes():
    keys = [block.SignerKey(urandom(32)) for i in range(3)]
    x = block.ExecutiveSpawn(
        signer=block.SignerKey(urandom(32)),
        memo=urandom(32)
    )
    y = block.ExecutiveSpawn.decode(x.encode())
    assert x == y
    x = block.ExecutiveSpawn(
        signer=block.SignerList(keys, 3),
        memo=urandom(0x100)
    )
    y = block.ExecutiveSpawn.decode(x.encode())
    assert x == y
    y = block.ExecutiveSpawn.decode(x.encode() + urandom(32))
    assert x == y
    assert len(x.encode()) == x.size


def test_executive_spawn_signers():
    keys = [block.SignerKey(urandom(32)) for i in range(3)]
    x = block.ExecutiveSpawn(
        signer=keys[0],
        memo=urandom(32)
    )
    assert x.signers == [keys[0]]
    x = block.ExecutiveSpawn(
        signer=block.SignerList(keys, 3),
        memo=urandom(32)
    )
    assert x.signers == keys


def test_asset_spawn_serdes():
    keys = [block.SignerKey(urandom(32)) for i in range(3)]
    x = block.AssetSpawn(
        signer=keys[0],
        memo=urandom(32),
        lock=False
    )
    y = block.AssetSpawn.decode(x.encode())
    assert x == y
    x = block.AssetSpawn(
        signer=block.SignerList(keys, 3),
        memo=urandom(32),
        lock=False
    )
    y = block.AssetSpawn.decode(x.encode())
    assert x == y
    x = block.AssetSpawn(
        signer=block.SignerList(keys, 3),
        memo=urandom(32),
        lock=True
    )
    y = block.AssetSpawn.decode(x.encode())
    assert x == y
    y = block.AssetSpawn.decode(x.encode() + urandom(32))
    assert x == y
    assert len(x.encode()) == x.size


def test_asset_spawn_signers():
    keys = [block.SignerKey(urandom(32)) for i in range(3)]
    x = block.AssetSpawn(
        signer=keys[0]
    )
    assert x.signers == keys[:1]
    x = block.AssetSpawn(
        signer=block.SignerList(keys, 3)
    )
    assert x.signers == keys


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


def test_transaction_serdes():
    x = block.Transaction(
        inputs=[
            block.PublisherSpend(
                block=int.from_bytes(urandom(8), 'little'),
                signer=block.SignerKey(urandom(32)),
                memo=urandom(0x100)
            ),
            block.ExecutiveSpend(
                block=int.from_bytes(urandom(8), 'little'),
                signer=block.SignerKey(urandom(32)),
                memo=urandom(0x100)
            ),
            block.UTXOSpend(
                utxo=block.UTXORefByHash(
                    tx_hash=block.TransactionHash(urandom(32)),
                    output=int.from_bytes(urandom(2), 'little')
                ),
                signer=block.SignerKey(urandom(32)),
                memo=urandom(0x100)
            ),
            block.AssetSpawn(
                signer=block.SignerKey(urandom(32)),
                memo=urandom(0x100)
            ),
            block.ExecutiveSpawn(
                signer=block.SignerKey(urandom(32)),
                memo=urandom(0x100)
            )
        ],
        outputs=[
            block.UTXOSpawn(
                asset=block.SignerHash(urandom(32)),
                signer=block.SignerHash(urandom(32)),
                units=int.from_bytes(urandom(8), 'little')
            ),
            block.ExecutiveVote(
                executive=block.SignerHash(urandom(32)),
                units=int.from_bytes(urandom(8), 'little'),
                memo=b'hello'
            )
        ],
        signatures=[block.Signature(urandom(64)) for i in range(5)]
    )
    y = block.Transaction.decode(x.encode())
    assert x == y
    y = block.Transaction.decode(x.encode() + urandom(32))
    assert x == y
    assert len(x.encode()) == x.size


def test_transaction_signers():
    keys = [block.SignerKey(urandom(32)) for i in range(3)]
    x = block.Transaction(
        inputs=[
            block.PublisherSpend(
                block=int.from_bytes(urandom(8), 'little'),
                signer=block.SignerList(
                    signers=keys, threshold=3
                )
            ),
            block.PublisherSpend(
                block=int.from_bytes(urandom(8), 'little'),
                signer=block.SignerList(
                    signers=keys, threshold=3
                )
            )
        ],
        outputs=[]
    )
    assert x.signers == keys


@pytest.mark.asyncio
async def test_transaction_hash():
    x = block.Transaction(
        inputs=[
            block.PublisherSpend(
                block=int.from_bytes(urandom(8), 'little'),
                signer=block.SignerKey(urandom(32)),
                memo=urandom(0x100)
            ),
            block.ExecutiveSpend(
                block=int.from_bytes(urandom(8), 'little'),
                signer=block.SignerKey(urandom(32)),
                memo=urandom(0x100)
            ),
            block.UTXOSpend(
                utxo=block.UTXORefByHash(
                    tx_hash=block.TransactionHash(urandom(32)),
                    output=int.from_bytes(urandom(2), 'little')
                ),
                signer=block.SignerKey(urandom(32)),
                memo=urandom(0x100)
            ),
            block.AssetSpawn(
                signer=block.SignerKey(urandom(32)),
                memo=urandom(0x100)
            ),
            block.ExecutiveSpawn(
                signer=block.SignerKey(urandom(32)),
                memo=urandom(0x100)
            )
        ],
        outputs=[
            block.UTXOSpawn(
                asset=block.SignerHash(urandom(32)),
                signer=block.SignerHash(urandom(32)),
                units=int.from_bytes(urandom(8), 'little')
            ),
            block.ExecutiveVote(
                executive=block.SignerHash(urandom(32)),
                units=int.from_bytes(urandom(8), 'little'),
                memo=b'hello'
            )
        ],
        signatures=[block.Signature(urandom(64)) for i in range(5)]
    )
    y = block.Transaction.decode(x.encode())
    h = await x.hash()
    assert (await y.hash()) == h
    x.signatures = []
    x._encoded = None
    assert (await x.hash()) == h


def test_parameters_serdes():
    x = block.Parameters(
        target = rand(32),
        block_reward = 100_000 * 10 ** 6,
        exec_fund = 0,
        utxo_fee = 2**64 // (1000 * 60 * 24 * 365),
        data_fee = 100_000,
        executive = block.SignerHash(urandom(32))
    )
    y = block.Parameters.decode(x.encode())
    assert x == y
    y = block.Parameters.decode(x.encode() + urandom(32))
    assert x == y
    assert len(x.encode()) == x.size


def test_block_header_serdes():
    x = block.BlockHeader(
        id=rand(8),
        timestamp=rand(8),
        prev_block=block.BlockHash(urandom(32)),
        publisher=block.SignerKey(urandom(32))
    )
    y = block.BlockHeader.decode(x.encode())
    assert x == y
    y = block.BlockHeader.decode(x.encode() + urandom(32))
    assert x == y
    assert len(x.encode()) == x.size
    x = block.BlockHeader(
        id=x.id,
        timestamp=x.timestamp,
        prev_block=x.prev_block,
        publisher=x.publisher,
        ntxs=rand(4),
        root_hash=block.TransactionListHash(urandom(32)),
        parameters=block.Parameters(
            target=rand(32),
            block_reward=rand(8),
            exec_fund=rand(8),
            utxo_fee=rand(8),
            data_fee=rand(8),
            executive=block.SignerHash(urandom(32))
        ),
        nonce=block.Nonce(urandom(32))
    )
    y = block.BlockHeader.decode(x.encode())
    assert x == y
    y = block.BlockHeader.decode(x.encode() + urandom(32))
    assert x == y
    assert len(x.encode()) == x.size


@pytest.mark.asyncio
async def test_block_header_hash():
    x = block.BlockHeader(
        id=rand(8),
        timestamp=rand(8),
        prev_block=block.BlockHash(urandom(32)),
        publisher=block.SignerKey(urandom(32))
    )
    h = await x.hash()
    assert isinstance(h, block.BlockHeaderHash)
    x = block.BlockHeader(
        id=x.id,
        timestamp=x.timestamp,
        prev_block=x.prev_block,
        publisher=x.publisher,
        ntxs=rand(4),
        root_hash=block.TransactionListHash(urandom(32)),
        parameters=block.Parameters(
            target=rand(32),
            block_reward=rand(8),
            exec_fund=rand(8),
            utxo_fee=rand(8),
            data_fee=rand(8),
            executive=block.SignerHash(urandom(32))
        ),
        nonce=block.Nonce(urandom(32))
    )
    h = await x.hash()
    assert isinstance(h, block.BlockHeaderHash)


@pytest.mark.asyncio
async def test_block_header_hash_nonce():
    x = block.BlockHeader(
        id=rand(8),
        timestamp=rand(8),
        prev_block=block.BlockHash(urandom(32)),
        publisher=block.SignerKey(urandom(32)),
        ntxs=rand(4),
        root_hash=block.TransactionListHash(urandom(32)),
        parameters=block.Parameters(
            target=rand(32),
            block_reward=rand(8),
            exec_fund=rand(8),
            utxo_fee=rand(8),
            data_fee=rand(8),
            executive=block.SignerHash(urandom(32))
        )
    )
    h = await x.hash()
    with pytest.raises(ValueError):
        g = await x.hash_nonce()
    x.nonce = block.Nonce(urandom(32))
    assert (await x.hash()) == h
    g = await x.hash_nonce()
    assert isinstance(g, block.BlockHash)


def test_block_serdes():
    x = block.Block(
        header=block.BlockHeader(
            id=rand(8),
            timestamp=rand(8),
            prev_block=block.BlockHash(urandom(32)),
            publisher=block.SignerKey(urandom(32)),
            ntxs=1,
            root_hash=block.TransactionListHash(urandom(32)),
            parameters=block.Parameters(
                target=rand(32),
                block_reward=rand(8),
                exec_fund=rand(8),
                utxo_fee=rand(8),
                data_fee=rand(8),
                executive=block.SignerHash(urandom(32))
            )
        ),
        transactions=[
            block.Transaction(
                inputs=[
                    block.PublisherSpend(
                        block=rand(8),
                        signer=block.SignerKey(urandom(32)),
                        memo=urandom(32)
                    )
                ],
                outputs=[
                    block.UTXOSpawn(
                        signer=block.SignerHash(urandom(32)),
                        units=rand(8),
                        memo=urandom(0x100)
                    )
                ]
            )
        ]
    )
    y = block.Block.decode(x.encode())
    assert x == y
    y = block.Block.decode(x.encode() + urandom(32))
    assert x == y
    assert len(x.encode()) == x.size


@pytest.mark.asyncio
async def test_block_hash_transactions():
    x = block.Block(
        header=block.BlockHeader(
            id=rand(8),
            timestamp=rand(8),
            prev_block=block.BlockHash(urandom(32)),
            publisher=block.SignerKey(urandom(32)),
            ntxs=1,
            root_hash=block.TransactionListHash(urandom(32))
        ),
        transactions=[
            block.Transaction(
                inputs=[
                    block.PublisherSpend(
                        block=rand(8),
                        signer=block.SignerKey(urandom(32)),
                        memo=urandom(32)
                    )
                ],
                outputs=[
                    block.UTXOSpawn(
                        signer=block.SignerHash(urandom(32)),
                        units=rand(8),
                        memo=urandom(0x100)
                    )
                ]
            )
        ]
    )
    h = await x.hash_transactions()
    assert isinstance(h, block.TransactionListHash)
    assert h != x.header.root_hash


@pytest.mark.asyncio
async def test_block_hash():
    x = block.Block(
        header=block.BlockHeader(
            id=rand(8),
            timestamp=rand(8),
            prev_block=block.BlockHash(urandom(32)),
            publisher=block.SignerKey(urandom(32)),
            parameters=block.Parameters(
                target=rand(32),
                block_reward=rand(8),
                exec_fund=rand(8),
                utxo_fee=rand(8),
                data_fee=rand(8),
                executive=block.SignerHash(urandom(32))
            ),
            nonce = block.Nonce(urandom(32))
        ),
        transactions=[
            block.Transaction(
                inputs=[
                    block.PublisherSpend(
                        block=rand(8),
                        signer=block.SignerKey(urandom(32)),
                        memo=urandom(32)
                    )
                ],
                outputs=[
                    block.UTXOSpawn(
                        signer=block.SignerHash(urandom(32)),
                        units=rand(8),
                        memo=urandom(0x100)
                    )
                ]
            )
        ]
    )
    with pytest.raises(ValueError):
        h = await x.hash()
    h = await x.hash(update_header=True)
    assert isinstance(h, block.BlockHash)
    assert x.header.ntxs == len(x.transactions)
    assert isinstance(x.header.root_hash, block.TransactionListHash)
