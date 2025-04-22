
from os import urandom
from arka._crypto import (
    keypair, sign, verify, key_exchange_vartime, mint, check_mint,
    keccak_800, keccak_1600
)
import keccak


def test_sign_happy_case():
    seed = urandom(32)
    kp = keypair(seed)
    sk, pk = kp[:32], kp[32:]
    assert seed == sk
    msg = urandom(32)
    sig = sign(kp, msg)
    assert verify(pk, sig, msg)


def test_sign_bad_pkey():
    xA = keypair(urandom(32))
    yQ = keypair(urandom(32))
    Q = yQ[32:]
    msg = urandom(32)
    sig = sign(xA, msg)
    assert not verify(Q, sig, msg)


def test_sign_bad_msg():
    xA = keypair(urandom(32))
    msg = urandom(32)
    sig = sign(xA, msg)
    assert not verify(xA[32:], sig, urandom(32))


def test_sign_bad_sig():
    xA = keypair(urandom(32))
    msg = urandom(32)
    assert not verify(xA[32:], urandom(64), msg)


def test_key_exchange_happy_case():
    xA = keypair(urandom(32))
    yQ = keypair(urandom(32))
    x, A = xA[:32], xA[32:]
    y, Q = yQ[:32], yQ[32:]
    s1 = key_exchange_vartime(x, Q)
    s2 = key_exchange_vartime(y, A)
    assert s1 == s2


def test_key_exchange_bad_key():
    xA = keypair(urandom(32))
    yQ = keypair(urandom(32))
    x, A = xA[:32], xA[32:]
    y, Q = yQ[:32], yQ[32:]
    s1 = key_exchange_vartime(x, Q)
    s2 = key_exchange_vartime(urandom(32), A)
    assert s1 != s2


def test_keccak_800():
    for x in (b'', urandom(32), urandom(64), 
        urandom(128), urandom(256)
    ):
        assert keccak_800(x) == keccak.keccak_800(x)
        assert keccak_800(x, 16) == keccak.keccak_800(x, 16)
        assert keccak_800(x, 64) == keccak.keccak_800(x, 64)
        assert keccak_800(x, 256) == keccak.keccak_800(x, 256)


def test_keccak_1600():
    for x in (b'', urandom(32), urandom(64), 
        urandom(128), urandom(256)
    ):
        assert keccak_1600(x) == keccak.keccak_1600(x)
        assert keccak_1600(x, 16) == keccak.keccak_1600(x, 16)
        assert keccak_1600(x, 64) == keccak.keccak_1600(x, 64)
        assert keccak_1600(x, 256) == keccak.keccak_1600(x, 256)


def test_mint_happy_case():
    diff_x, diff_n = 128, 8     # diff = 128 * 2 ** 8 = 32768
    limit = 2**30
    iteration = None
    while iteration is None:
        prefix = urandom(56)
        iteration: int = mint(prefix, diff_x, diff_n, limit)
    preimage = prefix + iteration.to_bytes(length=8, byteorder='little')
    assert check_mint(preimage, diff_x, diff_n)


def test_check_mint():
    diff_x, diff_n = 128, 8     # diff = 128 * 2 ** 8 = 32768
    limit = 2**30
    iteration = None
    while iteration is None:
        prefix = urandom(56)
        iteration: int = mint(prefix, diff_x, diff_n, limit)
    preimage = prefix + iteration.to_bytes(length=8, byteorder='little')
    assert check_mint(preimage, diff_x, diff_n)
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
