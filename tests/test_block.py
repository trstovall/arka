
from arka import block
from arka.crypto import keccak_800, keccak_1600
from os import urandom

import pytest
from asyncio import gather


rand = lambda n: int.from_bytes(urandom(n), 'little')


def make_pow():
    return block.POW(
        block.Nonce_32(bytes(32)), block.Nonce_32(bytes(32)),
        block.BlockHash(bytes(32)),
    )


async def set_pow(header):
    initial = (await header.hash()).value
    nonce = block.Nonce_32(urandom(32))
    final = await keccak_800(initial + nonce.value)
    header.pow = block.POW(block.Nonce_32(initial), nonce, block.BlockHash(final))


def assert_encoding_inverse(original, decoded):
    """Compare values and canonical bytes, excluding any trailing stream data."""
    assert original == decoded
    encoded = original.encode()
    assert isinstance(encoded, bytes)
    assert isinstance(decoded.encode(), bytes)
    assert decoded.encode() == encoded
    assert original.size == decoded.size == len(encoded)


def test_abstract_element():
    x = block.AbstractElement()
    assert x == block.AbstractElement()
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
    assert_encoding_inverse(x, y)
    y = A.decode(x.encode() + urandom(32))
    assert_encoding_inverse(x, y)
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
    assert_encoding_inverse(x, y)
    y = block.SignerHash.decode(x.encode() + urandom(32))
    assert_encoding_inverse(x, y)
    assert len(x.encode()) == x.size


def test_signer_key_serdes():
    x = block.SignerKey(urandom(32))
    assert x.encode() == x.value
    y = block.SignerKey.decode(x.encode())
    assert_encoding_inverse(x, y)
    y = block.SignerKey.decode(x.encode() + urandom(32))
    assert_encoding_inverse(x, y)
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
    assert_encoding_inverse(x, y)
    y = block.SignerList.decode(x.encode() + urandom(32))
    assert_encoding_inverse(x, y)
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


def test_signer_locked_serdes():
    keys = [block.SignerKey(urandom(32)) for i in range(4)]
    x = block.SignerLocked(
        hash_lock=block.Nonce_32(urandom(32)),
        hash_locked_signer=block.SignerList(keys[:2], 2),
        time_lock=rand(4),
        time_locked_signer=block.SignerHash(urandom(32))
    )
    y = block.SignerLocked.decode(x.encode())
    assert_encoding_inverse(x, y)
    y = block.SignerLocked.decode(x.encode() + urandom(32))
    assert_encoding_inverse(x, y)
    assert len(x.encode()) == x.size
    x = block.SignerLocked(
        hash_lock=block.Nonce_32(urandom(32)),
        hash_locked_signer=block.SignerHash(urandom(32)),
        time_lock=rand(4),
        time_locked_signer=block.SignerList(keys[2:], 2)
    )
    y = block.SignerLocked.decode(x.encode())
    assert_encoding_inverse(x, y)
    y = block.SignerLocked.decode(x.encode() + urandom(32))
    assert_encoding_inverse(x, y)
    assert len(x.encode()) == x.size
    x = block.SignerLocked(
        hash_lock=block.Nonce_32(urandom(32)),
        hash_locked_signer=block.SignerList(keys[:2], 2),
        time_lock=rand(4),
        time_locked_signer=block.SignerList(keys[2:], 2)
    )
    y = block.SignerLocked.decode(x.encode())
    assert_encoding_inverse(x, y)
    y = block.SignerLocked.decode(x.encode() + urandom(32))
    assert_encoding_inverse(x, y)
    assert len(x.encode()) == x.size
    x = block.SignerLocked(
        hash_lock=block.Nonce_32(urandom(32)),
        hash_locked_signer=block.SignerHash(urandom(32)),
        time_lock=rand(4),
        time_locked_signer=block.SignerHash(urandom(32))
    )
    y = block.SignerLocked.decode(x.encode())
    assert_encoding_inverse(x, y)
    y = block.SignerLocked.decode(x.encode() + urandom(32))
    assert_encoding_inverse(x, y)
    assert len(x.encode()) == x.size


def test_signer_locked_keys():
    keys = [block.SignerKey(urandom(32)) for i in range(4)]
    x = block.SignerLocked(
        hash_lock=block.Nonce_32(urandom(32)),
        hash_locked_signer=block.SignerList(keys[:2], 2),
        time_lock=rand(4),
        time_locked_signer=block.SignerHash(urandom(32))
    )
    assert x.keys == keys[:2]
    x = block.SignerLocked(
        hash_lock=block.Nonce_32(urandom(32)),
        hash_locked_signer=block.SignerHash(urandom(32)),
        time_lock=rand(4),
        time_locked_signer=block.SignerList(keys[2:], 2)
    )
    assert x.keys == keys[2:]
    x = block.SignerLocked(
        hash_lock=block.Nonce_32(urandom(32)),
        hash_locked_signer=block.SignerList(keys[:2], 2),
        time_lock=rand(4),
        time_locked_signer=block.SignerList(keys[2:], 2)
    )
    assert x.keys == keys
    x = block.SignerLocked(
        hash_lock=block.Nonce_32(urandom(32)),
        hash_locked_signer=block.SignerHash(urandom(32)),
        time_lock=rand(4),
        time_locked_signer=block.SignerHash(urandom(32))
    )
    with pytest.raises(ValueError):
        y = x.keys


@pytest.mark.asyncio
async def test_signer_locked_hash():
    keys = [block.SignerKey(urandom(32)) for i in range(4)]
    signers = [
        block.SignerList(keys[:2], 2),
        block.SignerList(keys[2:], 2)
    ]
    signer_hashes = await gather(*[s.hash() for s in signers])
    hash_lock_preimage = block.Nonce_32(urandom(32))
    hash_lock = block.Nonce_32(await keccak_800(hash_lock_preimage.value))
    time_lock = rand(4)
    x = block.SignerLocked(
        hash_lock=hash_lock_preimage,
        hash_locked_signer=signers[0],
        time_lock=time_lock,
        time_locked_signer=signer_hashes[1]
    )
    h_x = await x.hash()
    assert isinstance(h_x, block.SignerHash)
    y = block.SignerLocked(
        hash_lock=hash_lock,
        hash_locked_signer=signer_hashes[0],
        time_lock=time_lock,
        time_locked_signer=signers[1]
    )
    h_y = await y.hash()
    assert h_x == h_y
    z = block.SignerLocked(
        hash_lock=hash_lock,
        hash_locked_signer=signer_hashes[0],
        time_lock=time_lock,
        time_locked_signer=signer_hashes[1]
    )
    h_z = await z.hash()
    assert h_x == h_z
    w = block.SignerLocked(
        hash_lock=hash_lock_preimage,
        hash_locked_signer=signers[0],
        time_lock=time_lock,
        time_locked_signer=signers[1]
    )
    h_w = await w.hash()
    assert h_x == h_w


def test_utxo_ref_by_index_serdes():
    x = block.UTXORefByIndex(
        rand(8),
        rand(4),
        rand(2)
    )
    y = block.UTXORefByIndex.decode(x.encode())
    assert_encoding_inverse(x, y)
    y = block.UTXORefByIndex.decode(x.encode() + urandom(32))
    assert_encoding_inverse(x, y)
    assert len(x.encode()) == x.size


def test_utxo_ref_by_hash_serdes():
    x = block.UTXORefByHash(
        block.TransactionHash(urandom(32)),
        rand(2)
    )
    y = block.UTXORefByHash.decode(x.encode())
    assert_encoding_inverse(x, y)
    y = block.UTXORefByHash.decode(x.encode() + urandom(32))
    assert_encoding_inverse(x, y)
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


def test_transaction_input_keys():
    keys = [block.SignerKey(urandom(32)) for i in range(2)]
    x = block.TransactionInput(keys[0])
    assert x.keys == keys[:1]
    x = block.TransactionInput(block.SignerList(keys, 2))
    assert x.keys == keys


def test_utxo_spend_serdes():
    x = block.UTXOSpend(
        utxo=block.UTXORefByIndex(
            rand(8),
            rand(4),
            rand(2)
        )
    )
    y = block.UTXOSpend.decode(x.encode())
    assert_encoding_inverse(x, y)
    y = block.UTXOSpend.decode(x.encode() + urandom(32))
    assert_encoding_inverse(x, y)
    x = block.UTXOSpend(
        utxo=block.UTXORefByHash(
            block.TransactionHash(urandom(32)),
            rand(2)
        )
    )
    y = block.UTXOSpend.decode(x.encode())
    assert_encoding_inverse(x, y)
    y = block.UTXOSpend.decode(x.encode() + urandom(32))
    assert_encoding_inverse(x, y)
    x = block.UTXOSpend(
        utxo=block.UTXORefByHash(
            block.TransactionHash(urandom(32)),
            rand(2)
        ),
        signer=block.SignerLocked(
            hash_lock=block.Nonce_32(urandom(32)),
            hash_locked_signer=block.SignerList(
                [block.SignerKey(urandom(32)) for i in range(2)], 2
            ),
            time_lock=rand(4),
            time_locked_signer=block.SignerHash(urandom(32))
        )
    )
    y = block.UTXOSpend.decode(x.encode())
    assert_encoding_inverse(x, y)
    y = block.UTXOSpend.decode(x.encode() + urandom(32))
    assert_encoding_inverse(x, y)
    x = block.UTXOSpend(
        utxo=block.UTXORefByIndex(
            rand(8),
            rand(4),
            rand(2)
        ),
        time_lock=rand(4),
        signer=block.SignerList([
            block.SignerKey(urandom(32)) for i in range(2)
        ], 2),
        memo=urandom(0x100)
    )
    y = block.UTXOSpend.decode(x.encode())
    assert_encoding_inverse(x, y)
    y = block.UTXOSpend.decode(x.encode() + urandom(32))
    assert_encoding_inverse(x, y)
    assert len(x.encode()) == x.size


def test_utxo_spend_keys():
    keys = [block.SignerKey(urandom(32)) for i in range(3)]
    x = block.UTXOSpend(
        utxo=block.UTXORefByHash(
            block.TransactionHash(urandom(32)),
            rand(2)
        ),
        signer=keys[0]
    )
    assert x.keys == keys[:1]
    x.signer = block.SignerList(keys, 3)
    assert x.keys == keys
    x.signer = None
    with pytest.raises(ValueError):
        y = x.keys


def test_publisher_spend_serdes():
    x = block.PublisherSpend(
        block=rand(8),
        signer=block.SignerKey(urandom(32)),
        memo=urandom(32)
    )
    y = block.PublisherSpend.decode(x.encode())
    assert_encoding_inverse(x, y)
    x.signer = block.SignerList(
        [block.SignerKey(urandom(32)) for i in range(3)], 3
    )
    y = block.PublisherSpend.decode(x.encode())
    assert_encoding_inverse(x, y)
    x = block.PublisherSpend(
        block=rand(8),
        memo=urandom(32)
    )
    y = block.PublisherSpend.decode(x.encode())
    assert_encoding_inverse(x, y)
    y = block.PublisherSpend.decode(x.encode() + urandom(32))
    assert_encoding_inverse(x, y)
    assert len(x.encode()) == x.size


def test_publisher_spend_keys():
    keys = [block.SignerKey(urandom(32)) for i in range(3)]
    x = block.PublisherSpend(
        block=rand(8),
        signer=keys[0],
        memo=urandom(32)
    )
    assert x.keys == [keys[0]]
    x = block.PublisherSpend(
        block=rand(8),
        signer=block.SignerList(keys, 3),
        memo=urandom(32)
    )
    assert x.keys == keys
    x = block.PublisherSpend(
        block=rand(8),
        memo=urandom(32)
    )
    with pytest.raises(ValueError):
        y = x.keys


def test_executive_spend_serdes():
    x = block.ExecutiveSpend(
        block=rand(8),
        signer=block.SignerKey(urandom(32)),
        memo=urandom(32)
    )
    y = block.ExecutiveSpend.decode(x.encode())
    assert_encoding_inverse(x, y)
    x.signer = block.SignerList(
        [block.SignerKey(urandom(32)) for i in range(3)], 3
    )
    y = block.ExecutiveSpend.decode(x.encode())
    assert_encoding_inverse(x, y)
    x = block.ExecutiveSpend(
        block=rand(8),
        memo=urandom(32)
    )
    y = block.ExecutiveSpend.decode(x.encode())
    assert_encoding_inverse(x, y)
    y = block.ExecutiveSpend.decode(x.encode() + urandom(32))
    assert_encoding_inverse(x, y)
    assert len(x.encode()) == x.size


def test_executive_spend_keys():
    keys = [block.SignerKey(urandom(32)) for i in range(3)]
    x = block.ExecutiveSpend(
        block=rand(8),
        signer=keys[0],
        memo=urandom(32)
    )
    assert x.keys == [keys[0]]
    x = block.ExecutiveSpend(
        block=rand(8),
        signer=block.SignerList(keys, 3),
        memo=urandom(32)
    )
    assert x.keys == keys
    x = block.ExecutiveSpend(
        block=rand(8),
        memo=urandom(32)
    )
    with pytest.raises(ValueError):
        y = x.keys


def test_executive_definition_serdes():
    keys = [block.SignerKey(urandom(32)) for i in range(3)]
    x = block.ExecutiveDefinition(
        executive=block.Nonce_16(urandom(16)),
        signer=block.SignerKey(urandom(32)),
        new_signer=block.SignerHash(urandom(32)),
        memo=urandom(32)
    )
    y = block.ExecutiveDefinition.decode(x.encode())
    assert_encoding_inverse(x, y)
    x = block.ExecutiveDefinition(
        executive=block.Nonce_16(urandom(16)),
        signer=block.SignerList(keys, 3),
        memo=urandom(0x100)
    )
    y = block.ExecutiveDefinition.decode(x.encode())
    assert_encoding_inverse(x, y)
    y = block.ExecutiveDefinition.decode(x.encode() + urandom(32))
    assert_encoding_inverse(x, y)
    assert len(x.encode()) == x.size


def test_executive_definition_keys():
    keys = [block.SignerKey(urandom(32)) for i in range(3)]
    x = block.ExecutiveDefinition(
        executive=block.Nonce_16(urandom(16)),
        signer=keys[0],
        new_signer=block.SignerHash(urandom(32)),
        memo=urandom(32)
    )
    assert x.keys == keys[:1]
    x = block.ExecutiveDefinition(
        executive=block.Nonce_16(urandom(16)),
        signer=block.SignerList(keys, 3),
        memo=urandom(32)
    )
    assert x.keys == keys


def test_asset_definition_serdes():
    keys = [block.SignerKey(urandom(32)) for i in range(3)]
    x = block.AssetDefinition(
        asset=block.Nonce_16(urandom(16)),
        signer=keys[0],
        new_signer=block.SignerHash(urandom(32)),
        memo=urandom(32),
        lock=False
    )
    y = block.AssetDefinition.decode(x.encode())
    assert_encoding_inverse(x, y)
    x = block.AssetDefinition(
        asset=block.Nonce_16(urandom(16)),
        signer=block.SignerList(keys, 3),
        memo=urandom(32),
        lock=False
    )
    y = block.AssetDefinition.decode(x.encode())
    assert_encoding_inverse(x, y)
    x = block.AssetDefinition(
        asset=block.Nonce_16(urandom(16)),
        signer=block.SignerList(keys, 3),
        memo=urandom(32),
        lock=True
    )
    y = block.AssetDefinition.decode(x.encode())
    assert_encoding_inverse(x, y)
    y = block.AssetDefinition.decode(x.encode() + urandom(32))
    assert_encoding_inverse(x, y)
    assert len(x.encode()) == x.size


def test_asset_definition_keys():
    keys = [block.SignerKey(urandom(32)) for i in range(3)]
    x = block.AssetDefinition(
        asset=block.Nonce_16(urandom(16)),
        signer=keys[0],
        new_signer=block.SignerHash(urandom(32))
    )
    assert x.keys == keys[:1]
    x = block.AssetDefinition(
        asset=block.Nonce_16(urandom(16)),
        signer=block.SignerList(keys, 3)
    )
    assert x.keys == keys


def test_arka_utxo_serdes():
    x = block.ArkaUTXO(
        signer=block.SignerHash(urandom(32)),
        memo=urandom(32)
    )
    y = block.ArkaUTXO.decode(x.encode())
    assert_encoding_inverse(x, y)
    y = block.ArkaUTXO.decode(x.encode())
    assert_encoding_inverse(x, y)
    x.signer = block.SignerKey(urandom(32))
    y = block.ArkaUTXO.decode(x.encode())
    assert_encoding_inverse(x, y)
    x.units = rand(15)
    y = block.ArkaUTXO.decode(x.encode())
    assert_encoding_inverse(x, y)
    x.block_reward = rand(15)
    y = block.ArkaUTXO.decode(x.encode())
    assert_encoding_inverse(x, y)
    x.exec_fund = rand(15)
    y = block.ArkaUTXO.decode(x.encode())
    assert_encoding_inverse(x, y)
    x.utxo_fee = rand(15)
    y = block.ArkaUTXO.decode(x.encode())
    assert_encoding_inverse(x, y)
    x.data_fee = rand(15)
    y = block.ArkaUTXO.decode(x.encode())
    assert_encoding_inverse(x, y)
    y = block.ArkaUTXO.decode(x.encode() + urandom(32))
    assert_encoding_inverse(x, y)
    assert len(x.encode()) == x.size


def test_asset_utxo_serdes():
    x = block.AssetUTXO(
        asset=block.Nonce_16(urandom(16)),
        signer=block.SignerHash(urandom(32)),
        units=rand(15),
        memo=urandom(32)
    )
    y = block.AssetUTXO.decode(x.encode())
    assert_encoding_inverse(x, y)
    x.signer = block.SignerKey(urandom(32))
    y = block.AssetUTXO.decode(x.encode())
    assert_encoding_inverse(x, y)
    x.signer = None
    y = block.AssetUTXO.decode(x.encode())
    assert_encoding_inverse(x, y)
    x.units = None
    y = block.AssetUTXO.decode(x.encode())
    assert_encoding_inverse(x, y)
    y = block.AssetUTXO.decode(x.encode() + urandom(32))
    assert_encoding_inverse(x, y)
    assert len(x.encode()) == x.size


def test_executive_vote_serdes():
    x = block.ExecutiveVote(
        executive=block.Nonce_16(urandom(16))
    )
    y = block.ExecutiveVote.decode(x.encode())
    assert_encoding_inverse(x, y)
    x.units = rand(15)
    y = block.ExecutiveVote.decode(x.encode())
    assert_encoding_inverse(x, y)
    x.memo = urandom(32)
    y = block.ExecutiveVote.decode(x.encode())
    assert_encoding_inverse(x, y)
    y = block.ExecutiveVote.decode(x.encode() + urandom(32))
    assert_encoding_inverse(x, y)
    assert len(x.encode()) == x.size


def test_transaction_serdes():
    x = block.Transaction(
        inputs=[
            block.PublisherSpend(
                block=rand(8),
                signer=block.SignerKey(urandom(32)),
                memo=urandom(0x100)
            ),
            block.ExecutiveSpend(
                block=rand(8),
                signer=block.SignerKey(urandom(32)),
                memo=urandom(0x100)
            ),
            block.UTXOSpend(
                utxo=block.UTXORefByHash(
                    tx_hash=block.TransactionHash(urandom(32)),
                    output=rand(2)
                ),
                signer=block.SignerKey(urandom(32)),
                memo=urandom(0x100)
            ),
            block.AssetDefinition(
                asset=block.Nonce_16(urandom(16)),
                signer=block.SignerKey(urandom(32)),
                memo=urandom(0x100)
            ),
            block.ExecutiveDefinition(
                executive=block.Nonce_16(urandom(16)),
                signer=block.SignerKey(urandom(32)),
                memo=urandom(0x100)
            )
        ],
        outputs=[
            block.ArkaUTXO(
                signer=block.SignerHash(urandom(32)),
                units=rand(15)
            ),
            block.AssetUTXO(
                asset=block.Nonce_16(urandom(16)),
                signer=block.SignerHash(urandom(32)),
                units=rand(15),
                memo=urandom(32)
            ),
            block.ExecutiveVote(
                executive=block.Nonce_16(urandom(16)),
                units=rand(15),
                memo=b'hello'
            )
        ],
        signatures=[block.Signature(urandom(64)) for i in range(5)]
    )
    y = block.Transaction.decode(x.encode())
    assert_encoding_inverse(x, y)
    x.signatures = []
    y = block.Transaction.decode(x.encode())
    assert_encoding_inverse(x, y)
    y = block.Transaction.decode(x.encode() + urandom(32))
    assert_encoding_inverse(x, y)
    assert len(x.encode()) == x.size


def test_transaction_keys():
    keys = [block.SignerKey(urandom(32)) for i in range(3)]
    x = block.Transaction(
        inputs=[
            block.PublisherSpend(
                block=rand(8),
                signer=block.SignerList(
                    signers=keys, threshold=3
                )
            ),
            block.PublisherSpend(
                block=rand(8),
                signer=block.SignerList(
                    signers=keys, threshold=3
                )
            )
        ],
        outputs=[]
    )
    assert x.keys == keys


@pytest.mark.asyncio
async def test_transaction_hash():
    x = block.Transaction(
        inputs=[
            block.PublisherSpend(
                block=rand(8),
                signer=block.SignerKey(urandom(32)),
                memo=urandom(0x100)
            ),
            block.ExecutiveSpend(
                block=rand(8),
                signer=block.SignerKey(urandom(32)),
                memo=urandom(0x100)
            ),
            block.UTXOSpend(
                utxo=block.UTXORefByHash(
                    tx_hash=block.TransactionHash(urandom(32)),
                    output=rand(2)
                ),
                signer=block.SignerKey(urandom(32)),
                memo=urandom(0x100)
            ),
            block.AssetDefinition(
                asset=block.Nonce_16(urandom(16)),
                signer=block.SignerKey(urandom(32)),
                memo=urandom(0x100)
            ),
            block.ExecutiveDefinition(
                executive=block.Nonce_16(urandom(16)),
                signer=block.SignerKey(urandom(32)),
                memo=urandom(0x100)
            )
        ],
        outputs=[
            block.ArkaUTXO(
                signer=block.SignerHash(urandom(32)),
                units=rand(8)
            ),
            block.ExecutiveVote(
                executive=block.Nonce_16(urandom(16)),
                units=rand(8),
                memo=b'hello'
            )
        ],
        signatures=[block.Signature(urandom(64)) for i in range(5)]
    )
    y = block.Transaction.decode(x.encode())
    h = await x.hash()
    assert (await y.hash()) == h
    x.signatures = []
    assert (await x.hash()) == h


def test_parameters_serdes():
    x = block.Parameters(
        target=rand(32),
        block_reward=rand(15),
        exec_fund=rand(15),
        utxo_fee=rand(15),
        data_fee=rand(15),
        executive=block.Nonce_16(urandom(16))
    )
    y = block.Parameters.decode(x.encode())
    assert_encoding_inverse(x, y)
    y = block.Parameters.decode(x.encode() + urandom(32))
    assert_encoding_inverse(x, y)
    assert len(x.encode()) == x.size


def test_block_header_serdes():
    x = block.BlockHeader(
        id=rand(8),
        timestamp=rand(8),
        prev_block=block.BlockHash(urandom(32)),
        publisher=block.SignerKey(urandom(32))
    )
    y = block.BlockHeader.decode(x.encode())
    assert_encoding_inverse(x, y)
    y = block.BlockHeader.decode(x.encode() + urandom(32))
    assert_encoding_inverse(x, y)
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
            block_reward=rand(15),
            exec_fund=rand(15),
            utxo_fee=rand(15),
            data_fee=rand(15),
            executive=block.Nonce_16(urandom(16))
        ),
        pow=make_pow()
    )
    y = block.BlockHeader.decode(x.encode())
    assert_encoding_inverse(x, y)
    y = block.BlockHeader.decode(x.encode() + urandom(32))
    assert_encoding_inverse(x, y)
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
            executive=block.Nonce_16(urandom(16))
        ),
        pow=make_pow()
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
            executive=block.Nonce_16(urandom(16))
        )
    )
    h = await x.hash()
    with pytest.raises(ValueError):
        g = await x.hash_nonce()
    await set_pow(x)
    assert (await x.hash()) == h
    g = await x.hash_nonce()
    assert isinstance(g, block.BlockHash)


@pytest.mark.asyncio
async def test_block_serdes():
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
                block_reward=rand(15),
                exec_fund=rand(15),
                utxo_fee=rand(15),
                data_fee=rand(15),
                executive=block.Nonce_16(urandom(16))
            )
        ),
        transactions=block.TransactionList([
            block.Transaction(
                inputs=[
                    block.PublisherSpend(
                        block=rand(8),
                        signer=block.SignerKey(urandom(32)),
                        memo=urandom(32)
                    )
                ],
                outputs=[
                    block.ArkaUTXO(
                        signer=block.SignerHash(urandom(32)),
                        units=rand(15),
                        memo=urandom(0x100)
                    )
                ]
            )
        ])
    )
    y = await block.Block.decode(x.encode())
    assert_encoding_inverse(x, y)
    y = await block.Block.decode(x.encode() + urandom(32))
    assert_encoding_inverse(x, y)
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
        transactions=block.TransactionList([
            block.Transaction(
                inputs=[
                    block.PublisherSpend(
                        block=rand(8),
                        signer=block.SignerKey(urandom(32)),
                        memo=urandom(32)
                    )
                ],
                outputs=[
                    block.ArkaUTXO(
                        signer=block.SignerHash(urandom(32)),
                        units=rand(15),
                        memo=urandom(0x100)
                    )
                ]
            )
        ])
    )
    h = await x.transactions.hash()
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
                block_reward=rand(15),
                exec_fund=rand(15),
                utxo_fee=rand(15),
                data_fee=rand(15),
                executive=block.Nonce_16(urandom(16))
            ),
            pow=make_pow()
        ),
        transactions=block.TransactionList([
            block.Transaction(
                inputs=[
                    block.PublisherSpend(
                        block=rand(8),
                        signer=block.SignerKey(urandom(32)),
                        memo=urandom(32)
                    )
                ],
                outputs=[
                    block.ArkaUTXO(
                        signer=block.SignerHash(urandom(32)),
                        units=rand(15),
                        memo=urandom(0x100)
                    )
                ]
            )
        ])
    )
    with pytest.raises(ValueError):
        h = await x.hash()
    x.header.ntxs = len(x.transactions.transactions) or None
    x.header.root_hash = await x.transactions.hash()
    await set_pow(x.header)
    h = await x.hash(update_header=True)
    assert isinstance(h, block.BlockHash)
    assert x.header.ntxs == len(x.transactions.transactions)
    assert isinstance(x.header.root_hash, block.TransactionListHash)


BYTE_TYPES = [
    block.SignerHash, block.SignerKey, block.TransactionHash, block.Signature,
    block.BlockHeaderHash, block.BlockHash, block.TransactionListHash,
    block.Nonce_16, block.Nonce_32,
]


@pytest.mark.parametrize('cls', BYTE_TYPES, ids=lambda cls: cls.__name__)
@pytest.mark.parametrize('buffer_type', [bytes, bytearray, memoryview])
def test_byte_value_ownership(cls, buffer_type):
    backing = bytearray(range(cls.SIZE))
    expected = bytes(backing)
    value = cls(buffer_type(backing))
    decoded = cls.decode(buffer_type(backing))
    backing[:] = b'\xff' * len(backing)
    assert value.value == decoded.value == expected
    assert isinstance(value.value, bytes)
    assert isinstance(decoded.value, bytes)
    assert_encoding_inverse(value, decoded)


@pytest.mark.parametrize('cls', BYTE_TYPES, ids=lambda cls: cls.__name__)
def test_byte_value_hashability(cls):
    value = cls(bytes(range(cls.SIZE)))
    equal = cls.decode(value.encode())
    different = cls(b'\xff' * cls.SIZE)
    assert hash(value) == hash(equal)
    assert len({value, equal, different}) == 2
    assert {value: 'found'}[equal] == 'found'


@pytest.mark.parametrize('factory', [
    lambda: block.UTXORefByIndex(1, 2, 3),
    lambda: block.UTXORefByHash(block.TransactionHash(bytes(32)), 3),
], ids=['index', 'hash'])
def test_utxo_reference_hashability(factory):
    value = factory()
    equal = type(value).decode(value.encode())
    assert hash(value) == hash(equal)
    assert len({value, equal}) == 1
    assert {value: 'found'}[equal] == 'found'


def make_transaction(index=0, memo=b'memo'):
    return block.Transaction(
        inputs=[block.PublisherSpend(
            block=index, signer=block.SignerKey(bytes(range(32))), memo=memo,
        )],
        outputs=[block.ArkaUTXO(
            signer=block.SignerHash(bytes(range(32))), units=index + 1, memo=memo,
        )],
        signatures=[block.Signature(bytes(range(64)))],
    )


def make_header(count=0):
    return block.BlockHeader(
        id=1, timestamp=2, prev_block=block.BlockHash(bytes(32)),
        publisher=block.SignerKey(bytes(range(32))),
        ntxs=count or None,
        root_hash=block.TransactionListHash(bytes(32)) if count else None,
        pow=make_pow(),
    )


@pytest.mark.parametrize('buffer_type', [bytes, bytearray, memoryview])
@pytest.mark.parametrize('memo_size', [1, 255, 256, 65535])
def test_transaction_decoding_owns_buffers(buffer_type, memo_size):
    original = make_transaction(memo=b'm' * memo_size)
    encoded = original.encode()
    backing = bytearray(encoded + b'trailing bytes')
    decoded = block.Transaction.decode(buffer_type(backing))
    backing[:] = b'\xff' * len(backing)
    assert_encoding_inverse(original, decoded)
    assert isinstance(decoded.inputs[0].memo, bytes)
    assert isinstance(decoded.outputs[0].memo, bytes)
    assert isinstance(decoded.signatures[0].value, bytes)


@pytest.mark.parametrize('buffer_type', [bytearray, memoryview])
@pytest.mark.parametrize('operation', ['construct', 'decode'])
@pytest.mark.parametrize('factory', [
    lambda memo: block.PublisherSpend(1, memo=memo),
    lambda memo: block.ExecutiveSpend(1, memo=memo),
    lambda memo: block.UTXOSpend(
        block.UTXORefByIndex(1, 2, 3), memo=memo,
    ),
    lambda memo: block.ArkaUTXO(units=1, memo=memo),
    lambda memo: block.AssetDefinition(
        block.Nonce_16(bytes(16)), block.SignerKey(bytes(32)), memo=memo,
    ),
    lambda memo: block.ExecutiveDefinition(
        block.Nonce_16(bytes(16)), block.SignerKey(bytes(32)), memo=memo,
    ),
    lambda memo: block.AssetUTXO(block.Nonce_16(bytes(16)), memo=memo),
    lambda memo: block.ExecutiveVote(block.Nonce_16(bytes(16)), units=1, memo=memo),
], ids=['publisher-spend', 'executive-spend', 'utxo-spend', 'arka',
        'asset-definition', 'executive-definition', 'asset', 'vote'])
def test_memo_owns_buffer(factory, buffer_type, operation):
    original = factory(b'memo')
    encoded = original.encode()
    if operation == 'construct':
        backing = bytearray(b'memo')
        value = factory(buffer_type(backing))
    else:
        backing = bytearray(encoded)
        value = type(original).decode(buffer_type(backing))
    backing[:] = b'x' * len(backing)
    assert value.memo == b'memo'
    assert isinstance(value.memo, bytes)
    assert value.encode() == encoded


@pytest.mark.asyncio
@pytest.mark.parametrize('count', [0, 1, 2, 3, 5])
@pytest.mark.parametrize('buffer_type', [bytes, bytearray, memoryview])
async def test_transaction_list_encoding_inverse(count, buffer_type):
    original = block.TransactionList([make_transaction(i) for i in range(count)])
    backing = bytearray(original.encode())
    decoded = await block.TransactionList.decode(buffer_type(backing))
    backing[:] = b'\xff' * len(backing)
    assert_encoding_inverse(original, decoded)
    assert await original.hash() == await decoded.hash()


@pytest.mark.asyncio
@pytest.mark.parametrize('count', [0, 1, 2, 3, 5])
@pytest.mark.parametrize('merkle', [False, True])
async def test_transaction_list_hash_vectors(count, merkle):
    txs = block.TransactionList([make_transaction(i) for i in range(count)])
    leaves = [await keccak_1600(tx.encode(include_signatures=False))
              for tx in txs.transactions]
    # Explicit small trees exercise odd duplication at multiple levels.
    async def pair(left, right):
        return await keccak_1600(left + right)

    if not count:
        expected = None
    elif not merkle:
        expected = await keccak_1600(b''.join(leaves))
    elif count == 1:
        expected = leaves[0]
    elif count == 2:
        expected = await pair(leaves[0], leaves[1])
    elif count == 3:
        expected = await pair(await pair(leaves[0], leaves[1]),
                              await pair(leaves[2], leaves[2]))
    else:
        left = await pair(await pair(leaves[0], leaves[1]),
                          await pair(leaves[2], leaves[3]))
        last = await pair(leaves[4], leaves[4])
        expected = await pair(left, await pair(last, last))
    actual = await txs.hash(merkle=merkle)
    assert actual == (block.TransactionListHash(expected)
                      if expected is not None else None)
    if merkle:
        assert await txs.hash() == actual


@pytest.mark.asyncio
@pytest.mark.parametrize('count', [0, 1, 3])
@pytest.mark.parametrize('buffer_type', [bytes, bytearray, memoryview])
async def test_block_encoding_inverse_and_cached_transactions(count, buffer_type):
    original = block.Block(
        make_header(count),
        block.TransactionList([make_transaction(i) for i in range(count)]),
    )
    original.header.root_hash = await original.transactions.hash()
    await set_pow(original.header)
    digest = await original.hash(update_header=True)
    encoded = original.encode()
    backing = bytearray(encoded + b'trailing bytes')
    decoded = await block.Block.decode(buffer_type(backing))
    backing[:] = b'\xff' * len(backing)
    assert_encoding_inverse(original, decoded)
    assert await decoded.hash() == digest
    for before, after in zip(original.transactions.transactions,
                             decoded.transactions.transactions):
        assert_encoding_inverse(before, after)
        assert after._size == len(before.encode())
        assert after.digest == await before.hash()
        assert await after.hash() == await before.hash()


@pytest.mark.parametrize('ids', [[], [0], [1], [256], [1, 2, 257], [0, 0]])
@pytest.mark.parametrize('buffer_type', [bytes, bytearray, memoryview])
def test_block_summary_encoding_inverse(ids, buffer_type):
    original = block.BlockSummary(make_header(len(ids)), ids)
    backing = bytearray(original.encode() + b'trailing bytes')
    decoded = block.BlockSummary.decode(buffer_type(backing))
    backing[:] = b'\xff' * len(backing)
    assert_encoding_inverse(original, decoded)
