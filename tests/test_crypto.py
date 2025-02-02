
from os import urandom
from arka.crypto import keypair, sign, verify, key_exchange, mint, keccak_800


def test_sign_happy_case():
    seed = urandom(32)
    kp = keypair(seed)
    sk, pk = kp[:32], kp[32:]
    assert seed == sk
    msg = urandom(32)
    sm = sign(kp, msg)
    assert msg == sm[64:]
    assert verify(pk, sm)


def test_sign_bad_pkey():
    xA = keypair(urandom(32))
    yQ = keypair(urandom(32))
    Q = yQ[32:]
    msg = urandom(32)
    sm = sign(xA, msg)
    assert not verify(Q, sm)


def test_sign_bad_msg():
    xA = keypair(urandom(32))
    msg = urandom(32)
    sm = sign(xA, msg)
    sm = sm[:64] + urandom(32)
    assert not verify(xA[32:], sm)


def test_sign_bad_sig():
    xA = keypair(urandom(32))
    msg = urandom(32)
    sm = sign(xA, msg)
    sm = urandom(64) + msg
    assert not verify(xA[32:], sm)


def test_kex_happy_case():
    xA = keypair(urandom(32))
    yQ = keypair(urandom(32))
    x, A = xA[:32], xA[32:]
    y, Q = yQ[:32], yQ[32:]
    s1 = key_exchange(x, Q)
    s2 = key_exchange(y, A)
    assert s1 == s2


def test_mint_happy_case():
    key = urandom(32)
    diff = bytes([0xff, 0x08])
    nonce = urandom(32)
    limit = 2**30
    x = mint(key, diff, nonce, limit)
    digest = keccak_800(key + diff + x)
    assert digest[0] == 0xff
    assert digest[1] == 0x00

