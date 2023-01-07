
#define PY_SSIZE_T_CLEAN  /* Make "s#" use Py_ssize_t rather than int. */

#include "Python.h"

#include "string.h"
#include "stdint.h"
#include "stdlib.h"

#include "ed25519.h"


static PyObject * keypair(PyObject * self, PyObject * args);
static PyObject * sign(PyObject * self, PyObject * args);
static PyObject * verify(PyObject * self, PyObject * args);
static PyObject * key_exchange(PyObject * self, PyObject * args);


static PyMethodDef crypto_methods[] = {
    {"keypair", keypair, METH_VARARGS, "Generate 64-byte ed25519 keypair of (32-byte secret, 32-byte public key)."},
    {"sign", sign, METH_VARARGS, "Use 32-byte secret key and 32-byte message hash to generate 64-byte ed25519 signature."},
    {"verify", verify, METH_VARARGS, "Validate ed25519 signature for 32-byte message hash and 32-byte public key."},
    {"key_exchange", key_exchange, METH_VARARGS, "Generate ed25519 keypair from 32-byte secret, 32-byte public key, and 32-byte nonce."},
};


static struct PyModuleDef cryptomodule = {
    PyModuleDef_HEAD_INIT,
    "crypto",
    NULL,
    -1,
    crypto_methods
};


PyMODINIT_FUNC PyInit_crypto(void)
{
    PyObject * mod;

    if (!(mod = PyModule_Create(&cryptomodule)))
        return NULL;

    return mod;
}


int ed25519_keypair(
    unsigned char * pk,
    unsigned char * sk,
    const unsigned char * seed
) {
    unsigned char az[32];
    ge_p3 A;

    memmove(sk, seed, 32);
    keccak800(az, 32, sk, 32);
    az[0] &= 248;
    az[31] &= 63;
    az[31] |= 64;

    ge_scalarmult_base(& A, az);
    ge_p3_tobytes(pk, & A);

    memmove(sk + 32, pk, 32);
    return 0;
}

int ed25519_sign(
    unsigned char * sm,
    unsigned long long * smlen,
    const unsigned char * m,
        unsigned long long mlen,
        const unsigned char * sk
) {
    unsigned char pk[32];
    unsigned char az[64];
    unsigned char nonce[64];
    unsigned char hram[64];
    ge_p3 R;

    memmove(pk, sk + 32, 32);

    keccak800(az, 64, sk, 32);
    az[0] &= 248;
    az[31] &= 63;
    az[31] |= 64;

    * smlen = mlen + 64;
    memmove(sm + 64, m, mlen);
    memmove(sm + 32, az + 32, 32);
    keccak800(nonce, 64, sm + 32, mlen + 32);
    memmove(sm + 32, pk, 32);

    sc_reduce(nonce);
    ge_scalarmult_base( & R, nonce);
    ge_p3_tobytes(sm, & R);

    keccak800(hram, 64, sm, mlen + 64);
    sc_reduce(hram);
    sc_muladd(sm + 32, hram, az, nonce);

    return 0;
}

int ed25519_verify(
    unsigned char * m,
    unsigned long long * mlen,
    const unsigned char * sm,
        unsigned long long smlen,
        const unsigned char * pk
) {
    unsigned char pkcopy[32];
    unsigned char rcopy[32];
    unsigned char scopy[32];
    unsigned char h[64];
    unsigned char rcheck[32];
    ge_p3 A;
    ge_p2 R;

    if (smlen < 64) goto badsig;
    if (sm[63] & 224) goto badsig;
    if (ge_frombytes_negate_vartime( & A, pk) != 0) goto badsig;

    memmove(pkcopy, pk, 32);
    memmove(rcopy, sm, 32);
    memmove(scopy, sm + 32, 32);

    memmove(m, sm, smlen);
    memmove(m + 32, pkcopy, 32);
    keccak800(h, 64, m, smlen);
    sc_reduce(h);

    ge_double_scalarmult_vartime( & R, h, & A, scopy);
    ge_tobytes(rcheck, & R);
    if (bytes_equal(rcheck, rcopy) == 0) {
        memmove(m, m + 64, smlen - 64);
        memset(m + smlen - 64, 0, 64);
        * mlen = smlen - 64;
        return 0;
    }

    badsig:
        *
        mlen = -1;
    memset(m, 0, smlen);
    return -1;
}



int ed25519_key_exchange_vartime(
    unsigned char * keypair,
    const unsigned char * seed,
    const unsigned char * pkey,
    const unsigned char * nonce
) {
    unsigned char az[32];
    unsigned char pk[32];
    ge_p3 A;
    ge_p2 R;

    keccak800(az, 32, seed, 32);
    az[0] &= 248;
    az[31] &= 63;
    az[31] |= 64;

    if (ge_frombytes_negate_vartime(& A, pkey) != 0)
        return -1;

    ge_double_scalarmult_vartime(& R, az, & A, nonce);
    ge_tobytes(keypair, & R);

    keccak800(az, 32, keypair, 32);
    az[0] &= 248;
    az[31] &= 63;
    az[31] |= 64;

    ge_scalarmult_base(& A, az);
    ge_p3_tobytes(pk, & A);

    memmove(keypair + 32, pk, 32);

    return 0;
}


static PyObject * keypair(PyObject * self, PyObject * args) {

    PyObject *buff, *value;
    Py_buffer pybuf;
    uint8_t seed[32], sk[64], pk[32];


    if (!PyArg_ParseTuple(args, "O", & buff))
        goto _error;
    if (!PyObject_CheckBuffer(buff))
        goto _bad_buffer;
    if (PyObject_GetBuffer(buff, & pybuf, 0))
        goto _bad_buffer_deref_pybuf;
    if (pybuf.len != 32)
        goto _bad_buffer_len_deref_pybuf;
    if (PyBuffer_ToContiguous(seed, & pybuf, pybuf.len, 'C'))
        goto _bad_buffer_deref_pybuf;
    PyBuffer_Release(& pybuf);

    ed25519_keypair(pk, sk, seed);

    value = PyBytes_FromStringAndSize((const char *)sk, 64);
    return value;

_bad_buffer:
    PyErr_SetString(PyExc_ValueError, "input seed must be buffer of len 32.");
    goto _error;

_bad_buffer_deref_pybuf:
    PyErr_SetString(PyExc_TypeError, "input seed must be buffer of len 32.");
    goto _deref_pybuf;

_bad_buffer_len_deref_pybuf:
    PyErr_SetString(PyExc_ValueError, "input seed must be buffer of len 32.");
    goto _deref_pybuf;

_deref_pybuf:
    PyBuffer_Release(& pybuf);

_error:
    return NULL;
}