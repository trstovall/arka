"""Regression coverage for the 96-byte POW header field."""

import pytest

from arka import block
from arka.crypto import keccak_800


def make_pow():
    return block.POW(
        block.Nonce_32(b'\x11' * 32),
        block.Nonce_32(b'\x22' * 32),
        block.Nonce_32(b'\x33' * 32),
    )


def make_header(pow=None):
    return block.BlockHeader(
        id=1, timestamp=2, prev_block=block.BlockHash(bytes(32)),
        publisher=block.SignerKey(bytes(32)), pow=pow,
    )


@pytest.mark.parametrize('buffer_type', [bytes, bytearray, memoryview])
def test_pow_encoding_and_ownership(buffer_type):
    value = make_pow()
    expected = b'\x11' * 32 + b'\x22' * 32 + b'\x33' * 32
    assert value.encode() == expected
    assert value.size == 96
    backing = bytearray(expected + b'trailing')
    decoded = block.POW.decode(buffer_type(backing))
    backing[:] = bytes(len(backing))
    assert decoded == value
    assert decoded.encode() == expected
    assert decoded.initial_hash.value == expected[:32]
    assert decoded.nonce.value == expected[32:64]
    assert decoded.final_hash.value == expected[64:]


@pytest.mark.parametrize('length', [0, 31, 32, 63, 64, 95])
def test_pow_rejects_truncation(length):
    with pytest.raises(ValueError):
        block.POW.decode(bytes(length))


@pytest.mark.parametrize('position', [0, 1, 2])
def test_pow_rejects_invalid_components(position):
    components = [block.Nonce_32(bytes(32)) for _ in range(3)]
    components[position] = bytes(32)
    with pytest.raises(ValueError):
        block.POW(*components)


@pytest.mark.parametrize('present', [False, True])
def test_header_pow_round_trip(present):
    header = make_header(make_pow() if present else None)
    encoded = header.encode()
    assert len(encoded) == header.size == 81 + (96 if present else 0)
    assert bool(encoded[0] & 8) == present
    decoded = block.BlockHeader.decode(encoded + b'trailing')
    assert decoded == header
    assert decoded.encode() == encoded
    assert header.encode(include_pow=False) == make_header().encode()


def test_header_rejects_legacy_nonce_payload():
    encoded = bytearray(make_header().encode())
    encoded[0] |= 8
    with pytest.raises(ValueError):
        block.BlockHeader.decode(encoded + bytes(32))


@pytest.mark.asyncio
async def test_header_hash_excludes_entire_pow():
    header = make_header()
    expected = await header.hash()
    header.pow = make_pow()
    assert await header.hash() == expected


async def attach_pow(header):
    initial = (await header.hash()).value
    nonce = block.Nonce_32(b'\x42' * 32)
    final = await keccak_800(initial + nonce.value)
    header.pow = block.POW(block.Nonce_32(initial), nonce, block.Nonce_32(final))
    return block.BlockHash(final)


@pytest.mark.asyncio
async def test_pow_validates_both_hashes():
    header = make_header()
    with pytest.raises(ValueError, match='Missing POW'):
        await header.hash_nonce()
    expected = await attach_pow(header)
    assert await header.hash_nonce() == expected
    decoded = block.BlockHeader.decode(header.encode())
    assert await decoded.hash_nonce() == expected


@pytest.mark.asyncio
@pytest.mark.parametrize('component', ['initial_hash', 'nonce', 'final_hash', 'header'])
async def test_pow_rejects_tampering(component):
    header = make_header()
    await attach_pow(header)
    proof = header.pow
    fields = [proof.initial_hash, proof.nonce, proof.final_hash]
    if component == 'header':
        header.timestamp += 1
    else:
        index = ['initial_hash', 'nonce', 'final_hash'].index(component)
        corrupted = bytearray(fields[index].value)
        corrupted[0] ^= 1
        fields[index] = block.Nonce_32(corrupted)
        header.pow = block.POW(*fields)
    with pytest.raises(ValueError, match='Invalid POW'):
        await header.hash_nonce()


@pytest.mark.asyncio
@pytest.mark.parametrize('count', [0, 1, 2])
async def test_block_pow_framing(count):
    transactions = block.TransactionList([
        block.Transaction(outputs=[block.ArkaUTXO(units=i + 1)])
        for i in range(count)
    ])
    header = make_header()
    header.ntxs = count or None
    header.root_hash = await transactions.hash()
    expected = await attach_pow(header)
    value = block.Block(header, transactions)
    encoded = value.encode()
    assert len(encoded) == value.size
    decoded = await block.Block.decode(encoded)
    assert decoded == value
    assert decoded.encode() == encoded
    assert await decoded.hash() == expected
    if count:
        decoded.transactions.transactions.append(block.Transaction())
        with pytest.raises(ValueError, match='Invalid POW initial hash'):
            await decoded.hash(update_header=True)
