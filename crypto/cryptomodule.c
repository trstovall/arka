
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
static PyObject * djb2(PyObject * self, PyObject * args);
static PyObject * keccak_800(PyObject * self, PyObject * args);
static PyObject * keccak_1600(PyObject * self, PyObject * args);


static PyMethodDef crypto_methods[] = {
    {"keypair", keypair, METH_VARARGS, "Generate 64-byte ed25519 keypair of (32-byte seed, 32-byte public key)."},
    {"sign", sign, METH_VARARGS, "Use 32-byte secret key and 32-byte message hash to generate 64-byte ed25519 signature."},
    {"verify", verify, METH_VARARGS, "Validate ed25519 signature for 32-byte message hash and 32-byte public key."},
    {"key_exchange", key_exchange, METH_VARARGS, "Generate ed25519 keypair from 32-byte secret, 32-byte public key, and 32-byte nonce."},
    {"djb2", djb2, METH_VARARGS, "Hash string to 32-bit digest."},
    {"keccak_800", keccak_800, METH_VARARGS, "Perform 32-bit Keccak hash with 10*1 padding."},
    {"keccak_1600", keccak_1600, METH_VARARGS, "Perform 64-bit Keccak hash with 10*1 padding."},
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



static PyObject * keypair(PyObject * self, PyObject * args) {

    PyObject *buff;
    Py_buffer pybuf;
    uint8_t seed[32], sk[64], pk[32];


    if (!PyArg_ParseTuple(args, "O", & buff))
        goto _error;
    if (!PyObject_CheckBuffer(buff))
        goto _bad_buffer;
    if (PyObject_GetBuffer(buff, & pybuf, 0))
        goto _bad_buffer;
    if (pybuf.len != 32)
        goto _bad_buffer_len_deref_pybuf;
    if (PyBuffer_ToContiguous(seed, & pybuf, pybuf.len, 'C'))
        goto _bad_buffer_deref_pybuf;

    PyBuffer_Release(& pybuf);
    ed25519_keypair(pk, sk, seed);

    return PyBytes_FromStringAndSize((const char *)sk, 64);

_bad_buffer:
    PyErr_SetString(PyExc_ValueError, "input seed must be buffer of len 32.");
    goto _error;

_bad_buffer_len_deref_pybuf:
    PyErr_SetString(PyExc_ValueError, "input seed must be buffer of len 32.");
    goto _deref_pybuf;

_deref_pybuf:
    PyBuffer_Release(& pybuf);
_error:
    return NULL;
}


static PyObject * sign(PyObject * self, PyObject * args) {
    // srm = sign(keypair, hash_digest)

    PyObject *py_x_A, *py_m;
    Py_buffer c_x_A, c_m;
    uint8_t sm[64+32], m[32], x_A[64];

    if (!PyArg_ParseTuple(args, "OO", & py_x_A, & py_m))
        goto _error;

    if (!(PyObject_CheckBuffer(py_x_A) && PyObject_CheckBuffer(py_m)))
        goto _bad_buffs;

    if (PyObject_GetBuffer(py_x_A, & c_x_A, 0))
        goto _bad_buffs;

    if (PyObject_GetBuffer(py_m, & c_m, 0))
        goto _bad_buffs_deref_c_x_A;

    if (c_x.len != 64 || c_m.len != 32)
        goto _bad_buffs_len_deref_buffs;

    if (PyBuffer_ToContiguous(x_A, & c_x_A, 64, 'C'))
        goto _bad_buffs_deref_buffs;

    if (PyBuffer_ToContiguous(m, & c_m, 32, 'C'))
        goto _bad_buffs_deref_buffs;

    PyBuffer_Release(& c_x_A);
    PyBuffer_Release(& c_m);

    ed25519_sign(sm, 96, m, 32, x_A);

    return PyBytes_FromStringAndSize((const char *)sm, 96);

_bad_buffs_deref_buffs;
    PyErr_SetString(PyExc_TypeError, "input keypair must be 64 bytes and hash_digest must be of len 32.")
    goto _deref_c_m:

_bad_buffs_len_deref_buffs;
    PyErr_SetString(PyExc_TypeError, "input keypair must be 64 bytes and hash_digest must be of len 32.")
    goto _deref_c_m:

_bad_buffs_deref_c_x_A:
    PyErr_SetString(PyExc_TypeError, "input keypair must be 64 bytes and hash_digest must be of len 32.")
    goto _deref_c_x_A:

_bad_buffs:
    PyErr_SetString(PyExc_TypeError, "input keypair must be 64 bytes and hash_digest must be of len 32.")
    goto _error;

_deref_c_m:
    PyBuffer_Release(& c_m);
_deref_c_x_A:
    PyBuffer_Release(& c_x_A);
_error:
    return NULL;
}


static PyObject * verify(PyObject * self, PyObject * args) {
    // p = verify(key, signed_message_digest)

    PyObject *py_pk, *py_sm;
    Py_buffer c_pk, c_sm;
    uint8_t m[32], sm[64+32], pk[32];
    uint32_t mlen = 0;

     if (!PyArg_ParseTuple(args, "OO", & py_sm, & py_pk))
        goto _error;

    if (!(PyObject_CheckBuffer(py_sm) && PyObject_CheckBuffer(py_pk)))
        goto _bad_buffs;

    if (PyObject_GetBuffer(py_sm, & c_sm, 0))
        goto _bad_buffs;

    if (PyObject_GetBuffer(py_pk, & c_pk, 0))
        goto _bad_buffs_deref_c_sm;

    if (c_sm.len != 96 || c_pk.len != 32)
        goto _bad_buffs_len_deref_buffs;

    if (PyBuffer_ToContiguous(sm, & c_sm, 96, 'C'))
        goto _bad_buffs_deref_buffs;

    if (PyBuffer_ToContiguous(pk, & c_pk, 32, 'C'))
        goto _bad_buffs_deref_buffs;

    PyBuffer_Release(& c_sm);
    PyBuffer_Release(& c_pk);
   
    if (ed25519_verify(m, & mlen, sm, 96, pk))
        goto _error;

    return PyBytes_FromStringAndSize((const char *)m, 32);

_bad_buffs_deref_buffs;
    PyErr_SetString(PyExc_TypeError, "input signed_message_digest must be 96 bytes and pk must be of len 32.")
    goto _deref_c_pk:

_bad_buffs_len_deref_buffs;
    PyErr_SetString(PyExc_TypeError, "input signed_message_digest must be 96 bytes and pk must be of len 32.")
    goto _deref_c_pk;

_bad_buffs_deref_c_sm:
    PyErr_SetString(PyExc_TypeError, "input signed_message_digest must be 96 bytes and pk must be of len 32.")
    goto _deref_c_sm;

_bad_buffs:
    PyErr_SetString(PyExc_TypeError, "input signed_message_digest must be 96 bytes and pk must be of len 32.")
    goto _error;

_deref_c_pk:
    PyBuffer_Release(& c_pk);
_deref_c_sm:
    PyBuffer_Release(& c_sm);
_error:
    return NULL;
}
