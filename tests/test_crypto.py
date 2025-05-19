
from os import urandom
from arka import crypto, _crypto
import keccak
import pytest
import pytest_asyncio


def test_sign_happy_case():
    seed = urandom(32)
    kp = _crypto.keypair(seed)
    sk, pk = kp[:32], kp[32:]
    assert seed == sk
    msg = urandom(32)
    sig = _crypto.sign(kp, msg)
    assert _crypto.verify(pk, sig, msg)


@pytest.mark.asyncio
async def test_sign_happy_case_async():
    kp = await crypto.Keypair()
    hash = urandom(32)
    sig = await kp.sign(hash)
    verifier = await kp.verifier()
    assert await verifier.verify(sig, hash)


def test_sign_bad_pkey():
    xA = _crypto.keypair(urandom(32))
    yQ = _crypto.keypair(urandom(32))
    Q = yQ[32:]
    msg = urandom(32)
    sig = _crypto.sign(xA, msg)
    assert not _crypto.verify(Q, sig, msg)


@pytest.mark.asyncio
async def test_sign_bad_pkey_async():
    kp1 = await crypto.Keypair()
    kp2 = await crypto.Keypair()
    hash = urandom(32)
    sig = await kp1.sign(hash)
    verifier1 = await kp1.verifier()
    verifier2 = await kp2.verifier()
    assert await verifier1.verify(sig, hash)
    assert not await verifier2.verify(sig, hash)


def test_sign_bad_msg():
    xA = _crypto.keypair(urandom(32))
    msg = urandom(32)
    sig = _crypto.sign(xA, msg)
    assert not _crypto.verify(xA[32:], sig, urandom(32))


@pytest.mark.asyncio
async def test_sign_bad_msg_async():
    kp = await crypto.Keypair()
    hash = urandom(32)
    sig = await kp.sign(hash)
    verifier = await kp.verifier()
    assert await verifier.verify(sig, hash)
    assert not await verifier.verify(sig, urandom(32))


def test_sign_bad_sig():
    xA = _crypto.keypair(urandom(32))
    msg = urandom(32)
    assert not _crypto.verify(xA[32:], urandom(64), msg)


@pytest.mark.asyncio
async def test_sign_bad_sig_async():
    kp = await crypto.Keypair()
    hash = urandom(32)
    sig = await kp.sign(hash)
    verifier = await kp.verifier()
    assert await verifier.verify(sig, hash)
    assert not await verifier.verify(urandom(64), hash)


def test_key_exchange_happy_case():
    xA = _crypto.keypair(urandom(32))
    yQ = _crypto.keypair(urandom(32))
    x, A = xA[:32], xA[32:]
    y, Q = yQ[:32], yQ[32:]
    s1 = _crypto.key_exchange_vartime(x, Q)
    s2 = _crypto.key_exchange_vartime(y, A)
    assert s1 == s2



@pytest.mark.asyncio
async def test_key_exchange_happy_case_async():
    kp1 = await crypto.Keypair()
    kp2 = await crypto.Keypair()
    vk1 = await kp1.verifier()
    vk2 = await kp2.verifier()
    kp3 = await kp1.spawn(vk2)
    kp4 = await kp2.spawn(vk1)
    assert kp3._seed == kp4._seed


def test_key_exchange_bad_key():
    xA = _crypto.keypair(urandom(32))
    yQ = _crypto.keypair(urandom(32))
    x, A = xA[:32], xA[32:]
    y, Q = yQ[:32], yQ[32:]
    s1 = _crypto.key_exchange_vartime(x, Q)
    s2 = _crypto.key_exchange_vartime(urandom(32), A)
    assert s1 != s2


@pytest.mark.asyncio
async def test_key_exchange_bad_key_async():
    kp1 = await crypto.Keypair()
    kp2 = await crypto.Keypair()
    kp3 = await crypto.Keypair()
    vk1 = await kp1.verifier()
    vk2 = await kp2.verifier()
    kp4 = await kp1.spawn(vk2)
    kp5 = await kp3.spawn(vk1)
    assert kp4._seed != kp5._seed


def test_derive_key():
    pw = b'hello'
    salt = urandom(16)
    iters = 5_000_000
    key = _crypto.derive_key(pw, salt, iterations=iters)
    assert isinstance(key, bytes)
    assert len(key) == 32


@pytest.mark.asyncio
async def test_derive_key_async():
    pw = b'hello'
    salt = urandom(16)
    cipher = await crypto.Cipher(pw, salt)
    key = cipher._key
    assert isinstance(key, bytes)
    assert len(key) == 32


def test_encrypt():
    key = urandom(32)
    nonce = urandom(16)
    msg = urandom(32)
    ctext = _crypto.encrypt(key, nonce, msg)
    assert isinstance(ctext, bytes)
    assert len(ctext) == 32
    assert ctext != msg
    ptext = _crypto.encrypt(key, nonce, ctext)
    assert ptext == msg


@pytest.mark.asyncio
async def test_encrypt_async():
    cipher = crypto.Cipher(None, None)
    cipher._key = urandom(32)
    nonce = urandom(16)
    msg = urandom(32)
    ctext = await cipher.encrypt(nonce, msg)
    assert isinstance(ctext, bytes)
    assert len(ctext) == 32
    assert ctext != msg
    ptext = await cipher.encrypt(nonce, ctext)
    assert ptext == msg


def test_keccak_800():
    for x in (b'', urandom(32), urandom(64), 
        urandom(128), urandom(256)
    ):
        assert _crypto.keccak_800(x) == keccak.keccak_800(x)
        assert _crypto.keccak_800(x, 16) == keccak.keccak_800(x, 16)
        assert _crypto.keccak_800(x, 64) == keccak.keccak_800(x, 64)
        assert _crypto.keccak_800(x, 256) == keccak.keccak_800(x, 256)


@pytest.mark.asyncio
async def test_keccak_800_async():
    for x in (b'', urandom(32), urandom(64), 
        urandom(128), urandom(256)
    ):
        assert (await crypto.keccak_800(x)) == keccak.keccak_800(x)
        assert (await crypto.keccak_800(x, 16)) == keccak.keccak_800(x, 16)
        assert (await crypto.keccak_800(x, 64)) == keccak.keccak_800(x, 64)
        assert (await crypto.keccak_800(x, 256)) == keccak.keccak_800(x, 256)


def test_keccak_1600():
    for x in (b'', urandom(32), urandom(64), 
        urandom(128), urandom(256)
    ):
        assert _crypto.keccak_1600(x) == keccak.keccak_1600(x)
        assert _crypto.keccak_1600(x, 16) == keccak.keccak_1600(x, 16)
        assert _crypto.keccak_1600(x, 64) == keccak.keccak_1600(x, 64)
        assert _crypto.keccak_1600(x, 256) == keccak.keccak_1600(x, 256)


@pytest.mark.asyncio
async def test_keccak_1600_async():
    for x in (b'', urandom(32), urandom(64), 
        urandom(128), urandom(256)
    ):
        assert (await crypto.keccak_1600(x)) == keccak.keccak_1600(x)
        assert (await crypto.keccak_1600(x, 16)) == keccak.keccak_1600(x, 16)
        assert (await crypto.keccak_1600(x, 64)) == keccak.keccak_1600(x, 64)
        assert (await crypto.keccak_1600(x, 256)) == keccak.keccak_1600(x, 256)


def test_mint_happy_case():
    diff_x, diff_n = 128, 8     # diff = 128 * 2 ** 8 = 32768
    limit = 2**30
    iteration = None
    while iteration is None:
        prefix = urandom(56)
        iteration: int = _crypto.mint(prefix, diff_x, diff_n, limit)
    preimage = prefix + iteration.to_bytes(length=8, byteorder='little')
    assert _crypto.check_mint(preimage, diff_x, diff_n)


@pytest.mark.asyncio
async def test_mint_happy_case_async():
    diff = 128, 8     # diff = 128 * 2 ** 8 = 32768
    limit = 2**30
    iteration = None
    while iteration is None:
        prefix = urandom(56)
        iteration: int = await crypto.mint(prefix, diff, limit)
    preimage = prefix + iteration.to_bytes(length=8, byteorder='little')
    assert await crypto.check_mint(preimage, diff)


def test_check_mint():
    diff_x, diff_n = 128, 8     # diff = 128 * 2 ** 8 = 32768
    limit = 2**30
    iteration = None
    while iteration is None:
        prefix = urandom(56)
        iteration: int = _crypto.mint(prefix, diff_x, diff_n, limit)
    preimage = prefix + iteration.to_bytes(length=8, byteorder='little')
    assert _crypto.check_mint(preimage, diff_x, diff_n)
    # Use Python keccak module
    digest = keccak.keccak_800(preimage)
    # Test linear difficulty
    x = int.from_bytes(digest[:2], 'little')
    err = (x * diff_x) >> 16
    assert not err
    # Test exponential difficulty
    n = int.from_bytes(digest[2:32], 'little')
    success = ((n >> diff_n) << diff_n) == n
    assert success


@pytest.mark.asyncio
async def test_check_mint_async():
    diff_x, diff_n = 128, 8     # diff = 128 * 2 ** 8 = 32768
    diff = diff_x, diff_n
    limit = 2**30
    iteration = None
    while iteration is None:
        prefix = urandom(56)
        iteration: int = await crypto.mint(prefix, diff, limit)
    preimage = prefix + iteration.to_bytes(length=8, byteorder='little')
    assert await crypto.check_mint(preimage, diff)
    # Use Python keccak module
    digest = keccak.keccak_800(preimage)
    # Test linear difficulty
    x = int.from_bytes(digest[:2], 'little')
    err = (x * diff_x) >> 16
    assert not err
    # Test exponential difficulty
    n = int.from_bytes(digest[2:32], 'little')
    success = ((n >> diff_n) << diff_n) == n
    assert success
