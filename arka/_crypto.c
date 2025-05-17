
#define PY_SSIZE_T_CLEAN  /* Make "s#" use Py_ssize_t rather than int. */

#include "Python.h"

#include "string.h"
#include "stdint.h"
#include "stdlib.h"

#include "ed25519.h"


static PyObject * keypair(PyObject * self, PyObject * args);
static PyObject * sign(PyObject * self, PyObject * args);
static PyObject * verify(PyObject * self, PyObject * args);
static PyObject * key_exchange_vartime(PyObject * self, PyObject * args);
static PyObject * keccak_800(PyObject * self, PyObject * args, PyObject * kwargs);
static PyObject * keccak_1600(PyObject * self, PyObject * args, PyObject * kwargs);
static PyObject * mint(PyObject * self, PyObject * args);
static PyObject * check_mint(PyObject * self, PyObject * args);
static PyObject * djb2(PyObject * self, PyObject * args);


// Method definition table
static PyMethodDef crypto_methods[] = {
    {"keypair", keypair, METH_VARARGS, "Generate 64-byte ed25519 keypair of (32-byte seed, 32-byte public key)."},
    {"sign", sign, METH_VARARGS, "Use 64-byte keypair and 32-byte message hash to generate 64-byte ed25519 signature."},
    {"verify", verify, METH_VARARGS, "Validate ed25519 signature for 32-byte message hash and 32-byte public key."},
    {"key_exchange_vartime", key_exchange_vartime, METH_VARARGS, "Perform a variable-time key exchange using ed25519."},
    {"keccak_800", (PyCFunction)keccak_800, METH_VARARGS | METH_KEYWORDS, "Compute a Keccak-800 hash of a message."},
    {"keccak_1600", (PyCFunction)keccak_1600, METH_VARARGS | METH_KEYWORDS, "Compute a Keccak-1600 hash of a message."},
    {"mint", mint, METH_VARARGS, "Find nonce such that keccak800(prefix|iteration) ~= 0."},
    {"check_mint", check_mint, METH_VARARGS, "Check preimage against target difficulty."},
    {"djb2", djb2, METH_VARARGS, "Hash string to 32-bit digest."},
    {NULL, NULL, 0, NULL}  // Sentinel
};


// Module definition
static struct PyModuleDef cryptomodule = {
    PyModuleDef_HEAD_INIT,
    "_crypto",  // Module name
    "A Python extension module for cryptographic operations.",
    -1,         // Module state (not used here)
    crypto_methods
};


// Module initialization function
PyMODINIT_FUNC PyInit__crypto(void) {
    return PyModule_Create(&cryptomodule);
}


// Function to generate an ed25519 keypair from a seed
static PyObject* keypair(PyObject* self, PyObject* args) {
    Py_buffer seed_buffer;
    PyObject* result = NULL;
    PyThreadState* _save;

    // Parse the input argument (a buffer containing the seed)
    if (!PyArg_ParseTuple(args, "y*", &seed_buffer)) {
        return NULL;  // Return NULL on parsing failure (exception is set)
    }

    // Check if the seed is exactly 32 bytes
    if (seed_buffer.len != 32) {
        PyErr_SetString(PyExc_ValueError, "Seed must be exactly 32 bytes");
        PyBuffer_Release(&seed_buffer);
        return NULL;
    }

    // Get buffer for seed
    uint8_t* seed = (uint8_t*)seed_buffer.buf;
    uint8_t keypair[64];  // 32-byte secret key + 32-byte public key

    // Release the GIL before calling the library function
    _save = PyEval_SaveThread();

    // Call the ed25519_keypair function from the ed25519 library
    ed25519_keypair(keypair, seed);

    // Reacquire the GIL after the library call
    PyEval_RestoreThread(_save);

    // Release the Python buffer
    PyBuffer_Release(&seed_buffer);

    // Convert the 64-byte keypair to a Python bytes object
    result = PyBytes_FromStringAndSize((const char*)keypair, 64);

    // Return the keypair as a Python bytes object
    return result;
}


// Function to sign a message hash using an ed25519 keypair
static PyObject* sign(PyObject* self, PyObject* args) {
    Py_buffer keypair_buffer, message_hash_buffer;
    PyObject* result = NULL;
    PyThreadState* _save;

    // Parse the input arguments (keypair and message_hash buffers)
    if (!PyArg_ParseTuple(args, "y*y*", &keypair_buffer, &message_hash_buffer)) {
        return NULL;
    }

    // Check if the keypair is exactly 64 bytes
    if (keypair_buffer.len != 64) {
        PyErr_SetString(PyExc_ValueError, "Keypair must be exactly 64 bytes");
        PyBuffer_Release(&keypair_buffer);
        PyBuffer_Release(&message_hash_buffer);
        return NULL;
    }

    // Check if the message_hash is exactly 32 bytes
    if (message_hash_buffer.len != 32) {
        PyErr_SetString(PyExc_ValueError, "Message hash must be exactly 32 bytes");
        PyBuffer_Release(&keypair_buffer);
        PyBuffer_Release(&message_hash_buffer);
        return NULL;
    }

    // Prepare buffer for the signature
    uint8_t signature[64];
    uint8_t* keypair = (uint8_t*)keypair_buffer.buf;
    uint8_t* message_hash = (uint8_t*)message_hash_buffer.buf;

    // Release the GIL before calling the library function
    _save = PyEval_SaveThread();

    // Call the ed25519_sign function from the ed25519 library
    ed25519_sign(signature, message_hash, keypair);

    // Reacquire the GIL
    PyEval_RestoreThread(_save);

    // Release the Python buffers
    PyBuffer_Release(&keypair_buffer);
    PyBuffer_Release(&message_hash_buffer);

    // Convert the 64-byte signature to a Python bytes object
    result = PyBytes_FromStringAndSize((const char*)signature, 64);
    if (result == NULL) {
        return NULL;
    }

    // Return the signature
    return result;
}


// Function to verify a signature using an ed25519 public key
static PyObject* verify(PyObject* self, PyObject* args) {
    Py_buffer pub_key_buffer, signature_buffer, message_hash_buffer;
    PyThreadState* _save;
    int result;

    // Parse the input arguments (pub_key, signature, and message_hash buffers)
    if (!PyArg_ParseTuple(args, "y*y*y*", &pub_key_buffer, &signature_buffer, &message_hash_buffer)) {
        return NULL;
    }

    // Check if the pub_key is exactly 32 bytes
    if (pub_key_buffer.len != 32) {
        PyErr_SetString(PyExc_ValueError, "Public key must be exactly 32 bytes");
        PyBuffer_Release(&pub_key_buffer);
        PyBuffer_Release(&signature_buffer);
        PyBuffer_Release(&message_hash_buffer);
        return NULL;
    }

    // Check if the signature is exactly 64 bytes
    if (signature_buffer.len != 64) {
        PyErr_SetString(PyExc_ValueError, "Signature must be exactly 64 bytes");
        PyBuffer_Release(&pub_key_buffer);
        PyBuffer_Release(&signature_buffer);
        PyBuffer_Release(&message_hash_buffer);
        return NULL;
    }

    // Check if the message_hash is exactly 32 bytes
    if (message_hash_buffer.len != 32) {
        PyErr_SetString(PyExc_ValueError, "Message hash must be exactly 32 bytes");
        PyBuffer_Release(&pub_key_buffer);
        PyBuffer_Release(&signature_buffer);
        PyBuffer_Release(&message_hash_buffer);
        return NULL;
    }

    // Pointers to the buffer data
    uint8_t* pub_key = (uint8_t*)pub_key_buffer.buf;
    uint8_t* signature = (uint8_t*)signature_buffer.buf;
    uint8_t* message_hash = (uint8_t*)message_hash_buffer.buf;

    // Release the GIL before calling the library function
    _save = PyEval_SaveThread();

    // Call the ed25519_verify function from the ed25519 library
    result = ed25519_verify(pub_key, signature, message_hash);

    // Reacquire the GIL
    PyEval_RestoreThread(_save);

    // Release the Python buffers
    PyBuffer_Release(&pub_key_buffer);
    PyBuffer_Release(&signature_buffer);
    PyBuffer_Release(&message_hash_buffer);

    // Return True if verification succeeded (non-zero), False otherwise
    return PyBool_FromLong(result);
}


// Function to perform a variable-time key exchange using ed25519
static PyObject* key_exchange_vartime(PyObject* self, PyObject* args) {
    Py_buffer priv_key_buffer, pub_key_buffer;
    PyThreadState* _save;

    // Parse the input arguments (priv_key and pub_key buffers)
    if (!PyArg_ParseTuple(args, "y*y*", &priv_key_buffer, &pub_key_buffer)) {
        return NULL;
    }

    // Check if the priv_key is exactly 32 bytes
    if (priv_key_buffer.len != 32) {
        PyErr_SetString(PyExc_ValueError, "Private key must be exactly 32 bytes");
        PyBuffer_Release(&priv_key_buffer);
        PyBuffer_Release(&pub_key_buffer);
        return NULL;
    }

    // Check if the pub_key is exactly 32 bytes
    if (pub_key_buffer.len != 32) {
        PyErr_SetString(PyExc_ValueError, "Public key must be exactly 32 bytes");
        PyBuffer_Release(&priv_key_buffer);
        PyBuffer_Release(&pub_key_buffer);
        return NULL;
    }

    // Prepare buffers for the seed output and inputs
    uint8_t seed[32];
    uint8_t* priv_key = (uint8_t*)priv_key_buffer.buf;
    uint8_t* pub_key = (uint8_t*)pub_key_buffer.buf;

    // Release the GIL before calling the library function
    _save = PyEval_SaveThread();

    // Call the ed25519_key_exchange_vartime function from the ed25519 library
    int err = ed25519_key_exchange_vartime(seed, priv_key, pub_key);

    // Reacquire the GIL
    PyEval_RestoreThread(_save);

    // Release the Python buffers
    PyBuffer_Release(&priv_key_buffer);
    PyBuffer_Release(&pub_key_buffer);

    if (err) {
        PyErr_SetString(PyExc_ValueError, "Key exchange failed.");
        return NULL;
    }
    else {
        // Return the 32-byte seed as bytes
        return PyBytes_FromStringAndSize((const char*)seed, 32);
    }
}


// Function to compute a Keccak-800 hash
static PyObject* keccak_800(PyObject* self, PyObject* args, PyObject* kwargs) {
    Py_buffer message_buffer;
    uint64_t out_len = 32;  // Default output length
    PyObject* result = NULL;
    PyThreadState* _save;
    static char* kwlist[] = {"message", "out_len", NULL};

    // Parse the input arguments (message buffer and optional out_len)
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "y*|K", kwlist, &message_buffer, &out_len)) {
        return NULL;
    }

    // Create a Python bytes object for the output
    result = PyBytes_FromStringAndSize(NULL, out_len);
    if (result == NULL) {
        PyBuffer_Release(&message_buffer);
        return NULL;
    }

    // Get the writable buffer from the bytes object
    uint8_t* output = (uint8_t*)PyBytes_AS_STRING(result);
    uint8_t* message = (uint8_t*)message_buffer.buf;
    uint64_t msg_len = (uint64_t)message_buffer.len;

    // Release the GIL before calling the library function
    _save = PyEval_SaveThread();

    // Call the keccak800 function from the library
    keccak800(output, out_len, message, msg_len);

    // Reacquire the GIL
    PyEval_RestoreThread(_save);

    // Release the Python buffer
    PyBuffer_Release(&message_buffer);

    // Return the result
    return result;
}


// Function to compute a Keccak-1600 hash
static PyObject* keccak_1600(PyObject* self, PyObject* args, PyObject* kwds) {
    Py_buffer message_buffer;
    uint64_t out_len = 32;  // Default output length
    PyObject* result = NULL;
    PyThreadState* _save;
    static char* kwlist[] = {"message", "out_len", NULL};

    // Parse the input arguments (message buffer and optional out_len)
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "y*|K", kwlist, &message_buffer, &out_len)) {
        return NULL;
    }

    // Create a Python bytes object for the output with length out_len
    result = PyBytes_FromStringAndSize(NULL, (Py_ssize_t)out_len);
    if (result == NULL) {
        PyBuffer_Release(&message_buffer);
        return NULL;
    }

    // Get the writable buffer from the bytes object
    uint8_t* output = (uint8_t*)PyBytes_AS_STRING(result);
    uint8_t* message = (uint8_t*)message_buffer.buf;
    uint64_t msg_len = (uint64_t)message_buffer.len;

    // Release the GIL before calling the library function
    _save = PyEval_SaveThread();

    // Call the keccak1600 function from the library
    keccak1600(output, out_len, message, msg_len);

    // Reacquire the GIL
    PyEval_RestoreThread(_save);

    // Release the Python message buffer
    PyBuffer_Release(&message_buffer);

    // Return the result
    return result;
}

// Generate random preimages and check against target difficulty
static PyObject* mint(PyObject * self, PyObject * args) {
    Py_buffer prefix_buffer;
    uint64_t limit;
    uint8_t diff_x, diff_n;  // difficulty = x * 2 ** n
    PyThreadState* _save;

    // Parse the inputs
    if (!PyArg_ParseTuple(args, "y*BBK",
        &prefix_buffer, &diff_x, &diff_n, &limit
    )){
        return NULL;
    }

    // Check if preimage prefix is exactly 56 bytes
    if (prefix_buffer.len != 56) {
        PyErr_SetString(PyExc_ValueError, "Preimage prefix must be exactly 56 bytes");
        PyBuffer_Release(&prefix_buffer);
        return NULL;
    }

    // Pointer to prefix buffer
    uint8_t* prefix = (uint8_t*)prefix_buffer.buf;
    // preimage = prefix + iteration
    uint8_t preimage[64];
    // digest = keccak800(preimage)
    uint8_t digest[32];

    // Prepare preimage
    memcpy(preimage, prefix, 56);

    // Release the GIL before iterating through preimages
    _save = PyEval_SaveThread();

    // Try each preimage
    for (uint64_t iteration=0; iteration < limit; iteration++) {

        // Append 8-byte iteration to 56-byte preimage input
        for (int i=0; i<8; i++)
            preimage[56+i] = (iteration >> (i << 3)) & 0xff;

        // Generate random number
        keccak800(digest, 32, preimage, 64);
        
        // Check linear difficulty scaling
        if (((digest[0] | (digest[1] << 8)) * diff_x) >> 16)
            continue;

        // Check exponential difficulty scaling
        int j;
        int success = 1;
        // Check whole octets for zero
        for (j=2; j < 2 + (diff_n >> 3); j++)
            if (digest[j]) {
                success = 0;
                break;
            }
        if (!success)
            continue;
        // Check final bits for zero
        if ((diff_n & 7) && (digest[j] & ((1 << (diff_n & 7)) - 1)))
            continue;

        // Reacquire the GIL
        PyEval_RestoreThread(_save);

        // Release the Python prefix buffer
        PyBuffer_Release(&prefix_buffer);

        // Preimage is valid, return iteration
        return PyLong_FromUnsignedLongLong(iteration);
   }

    // Reacquire the GIL
    PyEval_RestoreThread(_save);

    // Release the Python prefix buffer
    PyBuffer_Release(&prefix_buffer);

    // Return None
    Py_RETURN_NONE;    
}


// Check preimage against target difficulty
static PyObject * check_mint(PyObject * self, PyObject * args) {
    Py_buffer preimage_buffer;
    uint8_t diff_x, diff_n;  // difficulty = x * 2 ** n
    PyThreadState* _save;

    // Parse the inputs
    if (!PyArg_ParseTuple(args, "y*BB",
        &preimage_buffer, &diff_x, &diff_n
    )){
        return NULL;
    }

    // Check if preimage prefix is exactly 56 bytes
    if (preimage_buffer.len != 64) {
        PyErr_SetString(PyExc_ValueError, "Preimage prefix must be exactly 64 bytes");
        PyBuffer_Release(&preimage_buffer);
        return NULL;
    }

    // Pointer to preimage buffer
    uint8_t* preimage = (uint8_t*)preimage_buffer.buf;
    // digest = keccak800(preimage)
    uint8_t digest[32];

    // Release the GIL before hashing preimage
    _save = PyEval_SaveThread();

    // Generate random number
    keccak800(digest, 32, preimage, 64);
        
    int success = 1;

    // Check linear difficulty scaling
    if (((digest[0] | (digest[1] << 8)) * diff_x) >> 16)
        success = 0;
    else {
        // Check exponential difficulty scaling
        int j;
        // Check whole octets for zero
        for (j=2; j < 2 + (diff_n >> 3); j++)
            if (digest[j]) {
                success = 0;
                break;
            }
        if (success) {
            // Check final bits for zero
            if ((diff_n & 7) && (digest[j] & ((1 << (diff_n & 7)) - 1)))
                success = 0;
        }
    }

    // Reacquire the GIL
    PyEval_RestoreThread(_save);

    // Release the Python preimage buffer
    PyBuffer_Release(&preimage_buffer);

    // Return preimage validity as bool
    return PyBool_FromLong(success);
}


// Hash uint8_t[N] to uint64_t
static PyObject * djb2(PyObject * self, PyObject * args) {

    Py_buffer string_buffer;
    uint64_t result = 5381;
    PyThreadState* _save;

    // Parse the inputs
    if (!PyArg_ParseTuple(args, "y*|K",
        &string_buffer, &result
    )){
        return NULL;
    }

    // Get buffer and length
    uint8_t* string = (uint8_t*)string_buffer.buf;
    uint64_t str_len = (uint64_t)string_buffer.len;

    // Release the GIL before hashing string
    _save = PyEval_SaveThread();

    // Hash the string
    for (uint64_t i=0; i < str_len; i++)
        result = (result << 5) + result + string[i];

    // Reacquire the GIL
    PyEval_RestoreThread(_save);

    // Release the Python string buffer
    PyBuffer_Release(&string_buffer);

    // Return result
    return PyLong_FromUnsignedLongLong(result);

}
