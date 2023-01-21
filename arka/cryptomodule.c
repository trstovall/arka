
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

_bad_buffer_deref_pybuf:
    PyErr_SetString(PyExc_ValueError, "input seed must be buffer of len 32.");
    goto _deref_pybuf;

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
    unsigned long long smlen = 0;

    if (!PyArg_ParseTuple(args, "OO", & py_x_A, & py_m))
        goto _error;

    if (!(PyObject_CheckBuffer(py_x_A) && PyObject_CheckBuffer(py_m)))
        goto _bad_buffs;

    if (PyObject_GetBuffer(py_x_A, & c_x_A, 0))
        goto _bad_buffs;

    if (PyObject_GetBuffer(py_m, & c_m, 0))
        goto _bad_buffs_deref_c_x_A;

    if (c_x_A.len != 64 || c_m.len != 32)
        goto _bad_buffs_len_deref_buffs;

    if (PyBuffer_ToContiguous(x_A, & c_x_A, 64, 'C'))
        goto _bad_buffs_deref_buffs;

    if (PyBuffer_ToContiguous(m, & c_m, 32, 'C'))
        goto _bad_buffs_deref_buffs;

    PyBuffer_Release(& c_x_A);
    PyBuffer_Release(& c_m);

    ed25519_sign(sm, &smlen, m, 32, x_A);

    if (smlen != 96)
        goto _bad_signature_deref_buffs;

    return PyBytes_FromStringAndSize((const char *)sm, 96);

_bad_signature_deref_buffs:
    PyErr_SetString(PyExc_Exception, "Unknown error when signing.");
    goto _deref_c_m;

_bad_buffs_deref_buffs:
    PyErr_SetString(PyExc_TypeError, "input keypair must be 64 bytes and hash_digest must be of len 32.");
    goto _deref_c_m;

_bad_buffs_len_deref_buffs:
    PyErr_SetString(PyExc_TypeError, "input keypair must be 64 bytes and hash_digest must be of len 32.");
    goto _deref_c_m;

_bad_buffs_deref_c_x_A:
    PyErr_SetString(PyExc_TypeError, "input keypair must be 64 bytes and hash_digest must be of len 32.");
    goto _deref_c_x_A;

_bad_buffs:
    PyErr_SetString(PyExc_TypeError, "input keypair must be 64 bytes and hash_digest must be of len 32.");
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
    unsigned long long mlen = 0;

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
   
    if (ed25519_verify(m, & mlen, sm, 96, pk) || mlen != 32)
        goto _error;

    return PyBytes_FromStringAndSize((const char *)m, 32);

_bad_buffs_deref_buffs:
    PyErr_SetString(PyExc_TypeError, "input signed_message_digest must be 96 bytes and pk must be of len 32.");
    goto _deref_c_pk;

_bad_buffs_len_deref_buffs:
    PyErr_SetString(PyExc_TypeError, "input signed_message_digest must be 96 bytes and pk must be of len 32.");
    goto _deref_c_pk;

_bad_buffs_deref_c_sm:
    PyErr_SetString(PyExc_TypeError, "input signed_message_digest must be 96 bytes and pk must be of len 32.");
    goto _deref_c_sm;

_bad_buffs:
    PyErr_SetString(PyExc_TypeError, "input signed_message_digest must be 96 bytes and pk must be of len 32.");
    goto _error;

_deref_c_pk:
    PyBuffer_Release(& c_pk);
_deref_c_sm:
    PyBuffer_Release(& c_sm);
_error:
    return NULL;
}


static PyObject * key_exchange(PyObject * self, PyObject * args) {

    PyObject *py_xA, *py_Q, *py_nonce;
    Py_buffer c_xA, c_Q, c_nonce;
    uint8_t xA[64], Q[32], nonce[32];
    uint8_t keypair[64];


    if (!PyArg_ParseTuple(args, "OOO", & py_xA, & py_Q, & py_nonce))
        goto _error;
    if (!(PyObject_CheckBuffer(py_xA) && PyObject_CheckBuffer(py_Q) && PyObject_CheckBuffer(py_nonce)))
        goto _bad_buffers;

    if (PyObject_GetBuffer(py_xA, & c_xA, 0))
        goto _bad_xA;
    if (PyObject_GetBuffer(py_xA, & c_xA, 0))
        goto _bad_Q_deref_xA;
    if (PyObject_GetBuffer(py_xA, & c_xA, 0))
        goto _bad_nonce_deref_Q;
    if (c_xA.len != 64 || c_Q.len != 32 || c_nonce.len != 32)
        goto _bad_buffer_len_deref_buffers;

    if (PyBuffer_ToContiguous(xA, & c_xA, 64, 'C'))
        goto _buffer_copy_fail_deref_buffers;
    if (PyBuffer_ToContiguous(Q, & c_Q, 32, 'C'))
        goto _buffer_copy_fail_deref_buffers;
    if (PyBuffer_ToContiguous(nonce, & c_nonce, 32, 'C'))
        goto _buffer_copy_fail_deref_buffers;

    PyBuffer_Release(& c_xA);
    PyBuffer_Release(& c_Q);
    PyBuffer_Release(& c_nonce);
    ed25519_key_exchange_vartime(keypair, xA, Q, nonce);

    return PyBytes_FromStringAndSize((const char *)keypair, 64);

_bad_buffers:
    PyErr_SetString(PyExc_TypeError, "input keypair, key, and nonce must be buffers");
    goto _error;

_bad_xA:
    PyErr_SetString(PyExc_ValueError, "Bad keypair");
    goto _error;

_bad_Q_deref_xA:
    PyErr_SetString(PyExc_ValueError, "Bad peer key.");
    goto _deref_xA;

_bad_nonce_deref_Q:
    PyErr_SetString(PyExc_ValueError, "Bad nonce buffer.");
    goto _deref_Q;

_bad_buffer_len_deref_buffers:
    PyErr_SetString(PyExc_ValueError, "input keypair, key, and nonce must be buffers of len 64, 32, 32.");
    goto _deref_nonce;

_buffer_copy_fail_deref_buffers:
    PyErr_SetString(PyExc_ValueError, "Failed to copy Py_buffers to C.");
    goto _deref_nonce;

_deref_nonce:
    PyBuffer_Release(& c_nonce);
_deref_Q:
    PyBuffer_Release(& c_Q);
_deref_xA:
    PyBuffer_Release(& c_xA);
_error:
    return NULL;
}


static PyObject * djb2(PyObject * self, PyObject * args) {

    PyObject *py_x;
    Py_buffer c_x;
    uint8_t x[32], y[4];
    uint32_t value = 5381;

    if (!PyArg_ParseTuple(args, "O", & py_x))
        goto _error;
    
    if (!PyObject_CheckBuffer(py_x))
        goto _bad_py_x;

    if (PyObject_GetBuffer(py_x, & c_x, 0))
        goto _bad_py_x;

    if (c_x.len != 32)
        goto _bad_x_len_deref_c_x;

    if (PyBuffer_ToContiguous(x, & c_x, 32, 'C'))
        goto _buffer_copy_fail_deref_c_x;

    PyBuffer_Release(& c_x);

    for (int i=0; i<32; i++)
        value = 33 * value + x[i];

    y[0] = value & 0xff;
    y[1] = (value >> 8) & 0xff;
    y[2] = (value >> 16) & 0xff;
    y[3] = (value >> 24) & 0xff;

    return PyBytes_FromStringAndSize((const char *)y, 4);

_buffer_copy_fail_deref_c_x:
    PyErr_SetString(PyExc_TypeError, "input value must be buffer of len 32.");
    goto _deref_c_x;

_bad_x_len_deref_c_x:
    PyErr_SetString(PyExc_TypeError, "input value must be buffer of len 32.");
    goto _deref_c_x;

_bad_py_x:
    PyErr_SetString(PyExc_TypeError, "input value must be buffer of len 32.");
    goto _error;

_deref_c_x:
    PyBuffer_Release(& c_x);

_error:
    return NULL;
}


static PyObject * keccak_800(PyObject * self, PyObject * args) {

    PyObject * py_x, * value;
    Py_buffer c_x;
    uint8_t *x, y[4096];
    uint32_t outlen = 32;

    if (!PyArg_ParseTuple(args, "O|i", & py_x, & outlen))
        goto _error;

    if (outlen > 4096)
        goto _bad_outlen;

    if (!PyObject_CheckBuffer(py_x))
        goto _bad_py_x;

    if (PyObject_GetBuffer(py_x, & c_x, 0))
        goto _bad_py_x;

    if (!(x = (uint8_t *) malloc(c_x.len)))
        goto _oom_deref_c_x;

    if (PyBuffer_ToContiguous(x, & c_x, c_x.len, 'C'))
        goto _buffer_copy_fail;

    PyBuffer_Release(& c_x);

    keccak800(y, outlen, x, c_x.len);

    value = PyBytes_FromStringAndSize((const char *)y, outlen);

    free(x);
    return value;

_buffer_copy_fail:
    PyErr_SetString(PyExc_TypeError, "input value must be buffer of len 32.");
    goto _deref_x;

_oom_deref_x:
    PyErr_NoMemory();
    goto _deref_x;

_oom_deref_c_x:
    PyErr_NoMemory();
    goto _deref_c_x;

_bad_py_x:
    PyErr_SetString(PyExc_TypeError, "input value must be buffer.");
    goto _error;

_bad_outlen:
    PyErr_SetString(PyExc_ValueError, "Output len must be >= 0 and <= 4096.");
    goto _error;

_deref_x:
    free(x);

_deref_c_x:
    PyBuffer_Release(& c_x);

_error:
    return NULL;
}


static PyObject * keccak_1600(PyObject * self, PyObject * args) {


    PyObject * py_x, * value;
    Py_buffer c_x;
    uint8_t *x, y[4096];
    uint64_t outlen = 32;

    if (!PyArg_ParseTuple(args, "O|i", & py_x, & outlen))
        goto _error;
    
    if (outlen > 4096)
        goto _bad_outlen;

    if (!PyObject_CheckBuffer(py_x))
        goto _bad_py_x;

    if (PyObject_GetBuffer(py_x, & c_x, 0))
        goto _bad_py_x;

    if (!(x = (uint8_t *) malloc(c_x.len)))
        goto _oom_deref_c_x;

    if (PyBuffer_ToContiguous(x, & c_x, c_x.len, 'C'))
        goto _buffer_copy_fail;

    PyBuffer_Release(& c_x);

    keccak1600(y, outlen, x, c_x.len);

    value = PyBytes_FromStringAndSize((const char *)y, outlen);

    free(x);
    return value;

_buffer_copy_fail:
    PyErr_SetString(PyExc_TypeError, "input value must be buffer of len 32.");
    goto _deref_x;

_oom_deref_x:
    PyErr_NoMemory();
    goto _deref_x;

_oom_deref_c_x:
    PyErr_NoMemory();
    goto _deref_c_x;

_bad_py_x:
    PyErr_SetString(PyExc_TypeError, "input value must be buffer.");
    goto _error;

_bad_outlen:
    PyErr_SetString(PyExc_ValueError, "Output len must be >= 0 and <= 4096.");
    goto _error;

_deref_x:
    free(x);

_deref_c_x:
    PyBuffer_Release(& c_x);

_error:
    return NULL;
}
