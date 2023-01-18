
#define PY_SSIZE_T_CLEAN  /* Make "s#" use Py_ssize_t rather than int. */
#include "Python.h"
#include "datetime.h"

#include "string.h"
#include "stdint.h"
#include "stdlib.h"


static PyObject * Error;
static PyObject * PackError;
static PyObject * UnpackError;


static PyObject * pack(PyObject * self, PyObject * args);
static PyObject * pack_nil(PyObject * self, PyObject * args);
static PyObject * pack_bool(PyObject * self, PyObject * args);
static PyObject * pack_int(PyObject * self, PyObject * args);
static PyObject * pack_float(PyObject * self, PyObject * args);
static PyObject * pack_bytes(PyObject * self, PyObject * args);
static PyObject * pack_utf8(PyObject * self, PyObject * args);
static PyObject * pack_array(PyObject * self, PyObject * args);
static PyObject * pack_map(PyObject * self, PyObject * args);
static PyObject * pack_ext(PyObject * self, PyObject * args);


static PyObject * unpack(PyObject * self, PyObject * args);
static PyObject * unpack_nil(PyObject * self, PyObject * args);
static PyObject * unpack_bool(PyObject * self, PyObject * args);
static PyObject * unpack_int(PyObject * self, PyObject * args);
static PyObject * unpack_float(PyObject * self, PyObject * args);
static PyObject * unpack_bytes(PyObject * self, PyObject * args);
static PyObject * unpack_utf8(PyObject * self, PyObject * args);
static PyObject * unpack_array(PyObject * self, PyObject * args);
static PyObject * unpack_map(PyObject * self, PyObject * args);
static PyObject * unpack_ext(PyObject * self, PyObject * args);


static PyMethodDef mpack_methods[] = {
    {"pack", pack, METH_VARARGS, "Serialize Python `object` to msgpack formatted `bytes`."},
    {"pack_nil", pack_nil, METH_VARARGS, "Serialize Python `None` to msgpack `nil`."},
    {"pack_bool", pack_bool, METH_VARARGS, "Serialize Python `bool` to msgpack `bool`."},
    {"pack_int", pack_int, METH_VARARGS, "Serialize Python `int` to msgpack `int`."},
    {"pack_float", pack_float, METH_VARARGS, "Serialize Python `float` to msgpack `float`."},
    {"pack_bytes", pack_bytes, METH_VARARGS, "Serialize Python buffer to msgpack `binary`."},
    {"pack_utf8", pack_utf8, METH_VARARGS, "Serialize Python `str` to msgpack `string`."},
    {"pack_array", pack_array, METH_VARARGS, "Serialize Python sequence to msgpack `array`."},
    {"pack_map", pack_map, METH_VARARGS, "Serialize Python map to msgpack `map`."},
    {"pack_ext", pack_ext, METH_VARARGS, "Serialize Python timestamp or custom object to msgpack `ext`."},

    {"unpack", unpack, METH_VARARGS, "Deserialize buffer to Python `object`."},
    {"unpack_nil", unpack_nil, METH_VARARGS, "Deserialize buffer to Python `None`."},
    {"unpack_bool", unpack_bool, METH_VARARGS, "Deserialize buffer to Python `bool`."},
    {"unpack_int", unpack_int, METH_VARARGS, "Deserialize buffer to Python `int`."},
    {"unpack_float", unpack_float, METH_VARARGS, "Deserialize buffer to Python `float`."},
    {"unpack_bytes", unpack_bytes, METH_VARARGS, "Deserialize buffer to Python `bytes`."},
    {"unpack_utf8", unpack_utf8, METH_VARARGS, "Deserialize buffer to Python `str`."},
    {"unpack_array", unpack_array, METH_VARARGS, "Deserialize buffer to Python list."},
    {"unpack_map", unpack_map, METH_VARARGS, "Deserialize buffer to Python dict."},
    {"unpack_ext", unpack_ext, METH_VARARGS, "Deserialize buffer to custom Python object."},
    {NULL, NULL, 0, NULL}   /* sentinel */
};


static struct PyModuleDef mpackmodule = {
    PyModuleDef_HEAD_INIT,
    "mpack",
    NULL,
    -1,
    mpack_methods
};


PyMODINIT_FUNC PyInit_mpack(void)
{
    PyObject * mod;

    PyDateTime_IMPORT;
    if (!(mod = PyModule_Create(&mpackmodule)))
        goto _unknown_error_mod;
    if (!(Error = PyErr_NewException("arka.mpack.Error", NULL, NULL)))
        goto _unknown_error_error_deref_mod;
    Py_INCREF(Error);
    if (PyModule_AddObject(mod, "Error", Error) < 0)
        goto _unknown_error_error_deref_error;
    if (!(PackError = PyErr_NewException("arka.mpack.PackError", Error, NULL)))
        goto _unknown_error_packerror_deref_error;
    Py_INCREF(PackError);
    if (PyModule_AddObject(mod, "PackError", Error) < 0)
        goto _unknown_error_packerror_deref_packerror;
    if (!(UnpackError = PyErr_NewException("arka.mpack.UnpackError", Error, NULL)))
        goto _unknown_error_unpackerror_deref_packerror;
    Py_INCREF(UnpackError);
    if (PyModule_AddObject(mod, "UnpackError", Error) < 0)
        goto _unknown_error_unpackerror_deref_unpackerror;

    return mod;

_unknown_error_mod:
    PyErr_SetString(PyExc_Exception, "Failed to create module.");
    goto _error;

_unknown_error_error_deref_mod:
    PyErr_SetString(PyExc_Exception, "Failed to create Error object.");
    goto _error_deref_mod;

_unknown_error_error_deref_error:
    PyErr_SetString(PyExc_Exception, "Failed to add Error object to module.");
    goto _error_deref_error;

_unknown_error_packerror_deref_error:
    PyErr_SetString(PyExc_Exception, "Failed to create PackError object.");
    goto _error_deref_error;

_unknown_error_packerror_deref_packerror:
    PyErr_SetString(PyExc_Exception, "Failed to add PackError object to module.");
    goto _error_deref_packerror;

_unknown_error_unpackerror_deref_packerror:
    PyErr_SetString(PyExc_Exception, "Failed to create UnpackError object.");
    goto _error_deref_packerror;

_unknown_error_unpackerror_deref_unpackerror:
    PyErr_SetString(PyExc_Exception, "Failed to add UnpackError object to module.");
    goto _error_deref_unpackerror;

_error_deref_unpackerror:
    Py_DECREF(UnpackError);
    Py_CLEAR(UnpackError);
_error_deref_packerror:
    Py_DECREF(PackError);
    Py_CLEAR(PackError);
_error_deref_error:
    Py_DECREF(Error);
    Py_CLEAR(Error);
_error_deref_mod:
    Py_DECREF(mod);
_error:
    return NULL;
}


typedef struct packer {
    int err;
    PyObject * obj;
    uint8_t * buffer;
    uint64_t seek;
    uint64_t len;
} packer;


packer * packer_init(PyObject * args);
PyObject * packer_close(packer * ctx);
int packer_make_fit(packer * ctx, size_t n);
int packer_pack(packer * ctx);
int packer_pack_int(packer * ctx);
int packer_pack_nil(packer * ctx);
int packer_pack_bool(packer * ctx);
int packer_pack_float(packer * ctx);
int packer_pack_bytes(packer * ctx);
int packer_pack_utf8(packer * ctx);
int packer_pack_array(packer * ctx);
int packer_pack_map(packer * ctx);
int packer_pack_ext(packer * ctx);


#define _check_pack_timestamp(obj) (                    \
    PyObject_HasAttrString(obj, "timestamp")            \
    && PyObject_HasAttrString(obj, "microsecond")       \
)


#define _check_pack_ext(obj) (                          \
    PyObject_HasAttrString((obj), "__msgpack__")        \
    || _check_pack_timestamp(obj)                       \
)


#define _pack_int(ctx, val, len) do {                           \
    for (int n = 8 * ((len) - 1); n >= 0; n -= 8)               \
        (ctx)->buffer[((ctx)->seek)++] = 0xff & ((val) >> n);   \
} while (0);


#define _unpack_int(val, ctx, len) do {                                     \
    switch (len) {                                                          \
        case 1: {                                                           \
            val |= ((ctx)->buffer[((ctx)->seek)++]);                        \
            break;                                                          \
        }                                                                   \
        case 2: {                                                           \
            for (int n = 8; n >= 0; n -= 8)                                 \
                val |= ((uint16_t) (ctx)->buffer[((ctx)->seek)++]) << n;    \
            break;                                                          \
        }                                                                   \
        case 4: {                                                           \
            for (int n = 24; n >= 0; n -= 8)                                \
                val |= ((uint32_t) (ctx)->buffer[((ctx)->seek)++]) << n;    \
            break;                                                          \
        }                                                                   \
        case 8: {                                                           \
            for (int n = 56; n >= 0; n -= 8)                                \
                val |= ((uint64_t) (ctx)->buffer[((ctx)->seek)++]) << n;    \
            break;                                                          \
        }                                                                   \
    }                                                                       \
} while (0);


static PyObject * pack(PyObject * self, PyObject * args)
{
    packer * ctx;

    if (!(ctx = packer_init(args)))
        goto _init_error;
    ctx->err = packer_pack(ctx);

    return packer_close(ctx);

    _init_error:
        return NULL;
}


#define PACK_METHOD(pymethod, check, cmethod, check_err)        \
static PyObject * pymethod(PyObject * self, PyObject * args)    \
{                                                               \
    packer * ctx;                                               \
                                                                \
    if (!(ctx = packer_init(args)))                             \
        goto _init_error;                                       \
    if (check(ctx->obj))                                        \
        ctx->err = cmethod(ctx);                                \
    else                                                        \
        PyErr_SetString(PackError, check_err);                  \
                                                                \
    return packer_close(ctx);                                   \
                                                                \
    _init_error:                                                \
        return NULL;                                            \
}

PACK_METHOD(
    pack_int, PyLong_Check, packer_pack_int, "`pack_int` input must be `int`."
)
PACK_METHOD(
    pack_nil, Py_IsNone, packer_pack_nil,  "`pack_nil` input must be `None`."
)
PACK_METHOD(
    pack_bool, PyBool_Check, packer_pack_bool, "`pack_bool` input must be `bool`."
)
PACK_METHOD(
    pack_float, PyFloat_Check, packer_pack_float, "`pack_float` input must be `float`."
)
PACK_METHOD(
    pack_bytes, PyObject_CheckBuffer, packer_pack_bytes, "`pack_bytes` input must implement buffer protocol."
)
PACK_METHOD(
    pack_utf8, PyUnicode_Check, packer_pack_utf8, "`pack_utf8` input must be `str`."
)
PACK_METHOD(
    pack_array, PySequence_Check, packer_pack_array, "`pack_array` input must implement sequence protocol."
)
PACK_METHOD(
    pack_map, PyMapping_Check, packer_pack_map, "`pack_map` input must implement mapping protocol."
)
PACK_METHOD(
    pack_ext, _check_pack_ext, packer_pack_ext, "`pack_ext` input must be timestamp or implement `__msgpack__`."
)

#undef PACK_METHOD


packer * packer_init(PyObject * args)
{
    PyObject * t;
    packer * ctx;
    
    if (!PyArg_ParseTuple(args, "O", & t))
        goto _bad_type;
    if (!(ctx = malloc(sizeof(packer))))
        goto _no_memory;
    ctx->err = 1;
    ctx->obj = t;
    ctx->seek = 0;
    ctx->len = 0;
    ctx->buffer = NULL;

    return ctx;

_bad_type:
    PyErr_SetString(PackError, "`pack` takes one positional argument `obj`.");
    goto _error;

_no_memory:
    PyErr_SetString(PyErr_NoMemory(), "Out of memory.");
    goto _error;

_error:
    return NULL;
}


PyObject * packer_close(packer * ctx)
{
    PyObject * value = NULL;

    if (!(ctx->err))
        value = PyBytes_FromStringAndSize((const char *)ctx->buffer, ctx->seek);
    if (ctx->buffer)
        free(ctx->buffer);
    free(ctx);
    if (!value && !PyErr_Occurred())
        goto _unknown_error;

    return value;

_unknown_error:
    PyErr_SetString(Error, "Unknown error occurred while packing.");
    goto _error;

_error:
    return NULL;
}


int packer_make_fit(packer * ctx, size_t n)
{
    uint8_t * t;

    if (ctx->seek + n > ctx->len) {
        while (ctx->len < ctx->seek + n)
            ctx->len += ctx->len ? ctx->len : 64;
        if (!(t = (uint8_t *) realloc(ctx->buffer, ctx->len)))
            goto _no_memory;
        ctx->buffer = t;
    }

    return 0;

_no_memory:
    PyErr_SetString(PyErr_NoMemory(), "Out of memory.");
    goto _error;

_error:
    return 1;
}


int packer_pack(packer * ctx)
{
    if (_check_pack_ext(ctx->obj))
        return packer_pack_ext(ctx);
    if (Py_IsNone(ctx->obj))
        return packer_pack_nil(ctx);
    if (PyBool_Check(ctx->obj))
        return packer_pack_bool(ctx);
    if (PyLong_Check(ctx->obj))
        return packer_pack_int(ctx);
    if (PyFloat_Check(ctx->obj))
        return packer_pack_float(ctx);
    if (PyObject_CheckBuffer(ctx->obj))
        return packer_pack_bytes(ctx);
    if (PyUnicode_Check(ctx->obj))
        return packer_pack_utf8(ctx);
    if (PySequence_Check(ctx->obj))
        return packer_pack_array(ctx);
    if (PyMapping_Check(ctx->obj))
        return packer_pack_map(ctx);

    PyErr_SetString(PackError, "Object type is not supported for packing.");
    goto _error;

_error:
    return 1;
}


int packer_pack_int(packer * ctx)
{
    int overflow;
    int64_t ivalue;
    uint64_t uvalue;
    
    ivalue = PyLong_AsLongLongAndOverflow(ctx->obj, & overflow);
    if (PyErr_Occurred())
        goto _unknown_error_ivalue;
    uvalue = (uint64_t) ivalue;
    if (!overflow) {                // LL_MIN <= int <= LL_MAX
        if (ivalue >= 0) {
            if (uvalue < (1ULL << 7)) {         // positive fixint
                if (packer_make_fit(ctx, 1))
                    goto _no_memory;
                _pack_int(ctx, uvalue, 1);
            }
            else if (uvalue < (1ULL << 8)) {    // uint 8
                if (packer_make_fit(ctx, 2))
                    goto _no_memory;
                _pack_int(ctx, 0xcc, 1);
                _pack_int(ctx, uvalue, 1);
            }
            else if (uvalue < (1ULL << 16)) {   // uint 16
                if (packer_make_fit(ctx, 3))
                    goto _no_memory;
                _pack_int(ctx, 0xcd, 1);
                _pack_int(ctx, uvalue, 2);
            }
            else if (uvalue < (1ULL << 32)) {   // uint 32
                if (packer_make_fit(ctx, 5))
                    goto _no_memory;
                _pack_int(ctx, 0xce, 1);
                _pack_int(ctx, uvalue, 4);
            }
            else {                              // uint 64
                if (packer_make_fit(ctx, 9))
                    goto _no_memory;
                _pack_int(ctx, 0xcf, 1);
                _pack_int(ctx, uvalue, 8);
            }
        }
        else {                                      // negative
            if (ivalue >= -(1LL << 5)) {            // negative fixint
                if (packer_make_fit(ctx, 1))
                    goto _no_memory;
                _pack_int(ctx, uvalue, 1);
            }
            else if (ivalue >= -(1LL << 7)) {       // int 8
                if (packer_make_fit(ctx, 2))
                    goto _no_memory;
                _pack_int(ctx, 0xd0, 1);
                _pack_int(ctx, uvalue, 1);
            }
            else if (ivalue >= -(1LL << 15)) {      // int 16
                if (packer_make_fit(ctx, 3))
                    goto _no_memory;
                _pack_int(ctx, 0xd1, 1);
                _pack_int(ctx, uvalue, 2);
            }
            else if (ivalue >= -(1LL << 31)) {      // int 32
                if (packer_make_fit(ctx, 5))
                    goto _no_memory;
                _pack_int(ctx, 0xd2, 1);
                _pack_int(ctx, uvalue, 4);
            }
            else {                                  // int 64
                if (packer_make_fit(ctx, 9))
                    goto _no_memory;
                _pack_int(ctx, 0xd3, 1);
                _pack_int(ctx, uvalue, 8);
            }
        }
    }
    else if (overflow > 0) {        // int > LL_MAX
        uvalue = PyLong_AsUnsignedLongLong(ctx->obj);
        if (PyErr_Occurred())         // int > INT_MAX
            goto _value_too_big;
        if (packer_make_fit(ctx, 9))
            goto _no_memory;
        _pack_int(ctx, 0xcf, 1);
        _pack_int(ctx, uvalue, 8);
    }
    else goto _value_too_low;       // int < INT_MIN

    return 0;

_unknown_error_ivalue:
    PyErr_SetString(Error, "Unknown error occured converting to C int.");
    goto _error;

_no_memory:
    goto _error;

_value_too_big:
    PyErr_SetString(PackError, "Unsigned int is too large to pack.");
    goto _error;

_value_too_low:
    PyErr_SetString(PackError, "Signed int is too large to pack.");
    goto _error;

_error:
    return 1;
}


int packer_pack_nil(packer * ctx)
{
    if (packer_make_fit(ctx, 1))
        goto _no_memory;
    _pack_int(ctx, 0xc0, 1);

    return 0;

_no_memory:
    goto _error;

_error:
    return 1;
}


int packer_pack_bool(packer * ctx)
{
    if (packer_make_fit(ctx, 1))
        goto _no_memory;
    _pack_int(ctx, (Py_IsTrue(ctx->obj) ? 0xc3 : 0xc2), 1);

    return 0;

_no_memory:
    goto _error;

_error:
    return 1;
}


int packer_pack_float(packer * ctx)
{
    float f;
    double d;
    uint32_t u32;
    uint64_t u64;

    d = PyFloat_AsDouble(ctx->obj);
    if (PyErr_Occurred())
        goto _unknown_error;
    f = (float) d;
    if (d == f) {                           // pack float32
        memcpy(& u32, & f, 4);
        if (packer_make_fit(ctx, 5))
            goto _no_memory;
        _pack_int(ctx, 0xca, 1);
        _pack_int(ctx, u32, 4);
    }
    else {                                  // pack float64
        memcpy(& u64, & d, 8);
        if (packer_make_fit(ctx, 9))
            goto _no_memory;
        _pack_int(ctx, 0xcb, 1);
        _pack_int(ctx, u64, 8);
    }

    return 0;

_unknown_error:
    PyErr_SetString(Error, "Unknown error occurred converting to C double.");
    goto _error;

_no_memory:
    goto _error;

_error:
    return 1;
}


int packer_pack_bytes(packer * ctx)
{
    Py_buffer buffer;

    if (PyObject_GetBuffer(ctx->obj, & buffer, 0))
        goto _unknown_error_buffer;
    if ((uint64_t) buffer.len < (1ULL << 8)) {
        if (packer_make_fit(ctx, 2 + buffer.len))
            goto _no_memory_deref_buffer;
        _pack_int(ctx, 0xc4, 1);
        _pack_int(ctx, buffer.len, 1);
    }
    else if ((uint64_t) buffer.len < (1ULL << 16)) {
        if (packer_make_fit(ctx, 3 + buffer.len))
            goto _no_memory_deref_buffer;
        _pack_int(ctx, 0xc5, 1);
        _pack_int(ctx, buffer.len, 2);
    }
    else if ((uint64_t) buffer.len < (1ULL << 32)) {
        if (packer_make_fit(ctx, 5 + buffer.len))
            goto _no_memory_deref_buffer;
        _pack_int(ctx, 0xc6, 1);
        _pack_int(ctx, buffer.len, 4);
    }
    else goto _value_too_big_deref_buffer;
    // encode data
    if (PyBuffer_ToContiguous(ctx->buffer + (ctx->seek), & buffer, buffer.len, 'C'))
        goto _unknown_error_ctx_buffer_deref_buffer;
    ctx->seek += buffer.len;
    PyBuffer_Release(& buffer);

    return 0;

_unknown_error_buffer:
    PyErr_SetString(Error, "Unknown error occurred converting bytes to C buffer.");
    goto _error;

_unknown_error_ctx_buffer_deref_buffer:
    PyErr_SetString(Error, "Unknown error occurred copying buffer to ctx->buffer.");
    goto _error_deref_buffer;

_no_memory_deref_buffer:
    goto _error_deref_buffer;

_value_too_big_deref_buffer:
    PyErr_SetString(PackError, "bytes object is too large to pack.");
    goto _error_deref_buffer;

_error_deref_buffer:
    PyBuffer_Release(& buffer);
_error:
    return 1;
}


int packer_pack_utf8(packer * ctx)
{
    Py_buffer buffer;
    PyObject * bytes;

    if (!(bytes = PyUnicode_AsUTF8String(ctx->obj)))
        goto _unknown_error_bytes;
    if (PyObject_GetBuffer(bytes, & buffer, 0))
        goto _unknown_error_buffer_deref_bytes;
    // encode type and length
    if ((uint64_t) buffer.len < (1ULL << 5)) {
        if (packer_make_fit(ctx, 1 + buffer.len))
            goto _no_memory_deref_buffer;
        _pack_int(ctx, 0xa0 | buffer.len, 1);
    }
    else if ((uint64_t) buffer.len < (1ULL << 8)) {
        if (packer_make_fit(ctx, 2 + buffer.len))
            goto _no_memory_deref_buffer;
        _pack_int(ctx, 0xd9, 1);
        _pack_int(ctx, buffer.len, 1);
    }
    else if ((uint64_t) buffer.len < (1ULL << 16)) {
        if (packer_make_fit(ctx, 3 + buffer.len))
            goto _no_memory_deref_buffer;
        _pack_int(ctx, 0xda, 1);
        _pack_int(ctx, buffer.len, 2);
    }
    else if ((uint64_t) buffer.len < (1ULL << 32)) {
        if (packer_make_fit(ctx, 5 + buffer.len))
            goto _no_memory_deref_buffer;
        _pack_int(ctx, 0xdb, 1);
        _pack_int(ctx, buffer.len, 4);
    }
    else goto _value_too_big_deref_buffer;
    // encode data
    if (PyBuffer_ToContiguous(ctx->buffer + (ctx->seek), & buffer, buffer.len, 'C'))
        goto _unknown_error_ctx_buffer_deref_buffer;
    ctx->seek += buffer.len;
    PyBuffer_Release(& buffer);
    Py_DECREF(bytes);

    return 0;

_unknown_error_bytes:
    PyErr_SetString(Error, "Unknown error occurred encoding str to bytes.");
    goto _error;

_unknown_error_buffer_deref_bytes:
    PyErr_SetString(Error, "Unknown error occurred converting str to C buffer.");
    goto _error_deref_bytes;

_unknown_error_ctx_buffer_deref_buffer:
    PyErr_SetString(Error, "Unknown error occurred copying Py_buffer to ctx->buffer.");
    goto _error_deref_buffer;

_no_memory_deref_buffer:
    goto _error_deref_buffer;

_value_too_big_deref_buffer:
    PyErr_SetString(PackError, "str object is too large to pack.");
    goto _error_deref_buffer;

_error_deref_buffer:
    PyBuffer_Release(& buffer);
_error_deref_bytes:
    Py_DECREF(bytes);
_error:
    return 1;
}


int packer_pack_array(packer * ctx)
{
    PyObject * array, * t, * item;
    Py_ssize_t i, len;
    int fast = 0;

    if ((array = PySequence_Fast(ctx->obj, "Sequence is not a fast sequence.")))
        fast = 1;
    else
        array = Py_NewRef(ctx->obj);
    // encode type and length
    len = fast ? PySequence_Fast_GET_SIZE(array) : PySequence_Length(array);
    if (len < 0)
        goto _unknown_error_len_deref_array;
    if (len < (1 << 4)) {
        if (packer_make_fit(ctx, 1))
            goto _no_memory_deref_array;
        _pack_int(ctx, 0x90 | len, 1);
    }
    else if ((uint64_t) len < (1ULL << 16)) {
        if (packer_make_fit(ctx, 3))
            goto _no_memory_deref_array;
        _pack_int(ctx, 0xdc, 1);
        _pack_int(ctx, len, 2);
    }
    else if ((uint64_t) len < (1ULL << 32)) {
        if (packer_make_fit(ctx, 5))
            goto _no_memory_deref_array;
        _pack_int(ctx, 0xdd, 1);
        _pack_int(ctx, len, 4);
    }
    else goto _value_too_big_deref_array;
    // encode items
    t = ctx->obj;
    for (i = 0; i < len; i++) {
        item = fast
            ? PySequence_Fast_GET_ITEM(array, i)
            : PySequence_GetItem(array, i);
        if (!item)
            goto _unknown_error_item_restore_ctx;
        ctx->obj = item;
        if (packer_pack(ctx))
            goto _pack_error_item_deref_item;
        if (!fast) Py_DECREF(item);
    }
    ctx->obj = t;
    Py_DECREF(array);

    return 0;

_unknown_error_len_deref_array:
    PyErr_SetString(Error, "Unknown error occurred obtaining array length.");
    goto _error_deref_array;

_unknown_error_item_restore_ctx:
    PyErr_SetString(Error, "Unknown error occurred obtaining item from array.");
    goto _error_restore_ctx;

_no_memory_deref_array:
    goto _error_deref_array;

_value_too_big_deref_array:
    PyErr_SetString(PackError, "Array is too large to pack.");
    goto _error_deref_array;

_pack_error_item_deref_item:
    goto _error_deref_item;

_error_deref_item:
    if (!fast) Py_DECREF(item);
_error_restore_ctx:
    ctx->obj = t;
_error_deref_array:
    if (fast) Py_DECREF(array);

    return 1;
}


int packer_pack_map(packer * ctx)
{
    PyObject * map, * keys, * key, * item, * t;
    Py_ssize_t i, len;
    int fast = 0;

    if (!(t = PyMapping_Keys(ctx->obj)))
        goto _unknown_error_keys;
    if (!(keys = PySequence_Fast(t, "keys sequence is not a list or tuple")))
        keys = t;
    else {
        Py_DECREF(t);
        fast = 1;
    }
    // encode type and length
    len = fast ?
        PySequence_Fast_GET_SIZE(keys)
        : PySequence_Length(keys);
    if (len < 0)
        goto _unknown_error_len_deref_keys;
    if ((uint64_t) len < (1ULL << 4)) {
        if (packer_make_fit(ctx, 1))
            goto _no_memory_deref_keys;
        _pack_int(ctx, 0x80 | len, 1);
    }
    else if ((uint64_t) len < (1ULL << 16)) {
        if (packer_make_fit(ctx, 3))
            goto _no_memory_deref_keys;
        _pack_int(ctx, 0xde, 1);
        _pack_int(ctx, len, 2);
    }
    else if ((uint64_t) len < (1ULL << 32)) {
        if (packer_make_fit(ctx, 5))
            goto _no_memory_deref_keys;
        _pack_int(ctx, 0xdf, 1);
        _pack_int(ctx, len, 4);
    }
    else goto _value_too_big_deref_keys;
    // encode items
    map = ctx->obj;
    for (i = 0; i < len; i++) {
        key = fast ?
            PySequence_Fast_GET_ITEM(keys, i)
            : PySequence_GetItem(keys, i);
        if (!key)
            goto _unknown_error_key_restore_ctx;
        ctx->obj = key;
        if (packer_pack(ctx))
            goto _pack_error_deref_key;
        if (!(item = PyObject_GetItem(map, key)))
            goto _unknown_error_item_deref_key;
        ctx->obj = item;
        if (packer_pack(ctx))
            goto _pack_error_deref_item;
        Py_DECREF(item);
        if (!fast) Py_DECREF(key);
    }
    ctx->obj = map;
    Py_DECREF(keys);

    return 0;

_unknown_error_keys:
    PyErr_SetString(Error, "Unknown error occurred obtaining keys for map.");
    goto _error;

_unknown_error_len_deref_keys:
    PyErr_SetString(Error, "Unknown error occurred obtaining size of map.");
    goto _error_deref_keys;

_unknown_error_key_restore_ctx:
    PyErr_SetString(Error, "Unknown error occurred obtaining map key.");
    goto _error_restore_ctx;

_unknown_error_item_deref_key:
    PyErr_SetString(Error, "Unknown error occurred obtaining item from map.");
    goto _error_deref_key;

_no_memory_deref_keys:
    goto _error_deref_keys;

_value_too_big_deref_keys:
    PyErr_SetString(PackError, "Map is too large to pack.");
    goto _error_deref_keys;

_pack_error_deref_key:
    goto _error_deref_key;

_pack_error_deref_item:
    goto _error_deref_item;

_error_deref_item:
    Py_DECREF(item);
_error_deref_key:
    if (!fast) Py_DECREF(key);
_error_restore_ctx:
    ctx->obj = map;
_error_deref_keys:
    Py_DECREF(keys);

_error:
    return 1;
}


int __pack_timestamp(packer * ctx)
{
    int overflow;
    uint32_t u32;
    uint64_t u64;
    int64_t i64;
    PyObject * attr, * attr2, * seconds, * microsec;

    // call obj.timestamp
    if (!(seconds = PyObject_CallMethod(ctx->obj, "timestamp", NULL)))
        goto _unknown_error_seconds;
    if (!PyFloat_Check(seconds))
        goto _unknown_error_seconds_deref_seconds;
    i64 = (int64_t) PyFloat_AsDouble(seconds);
    if (PyErr_Occurred())
        goto _unknown_error_seconds_deref_seconds;
    // get obj.microsec
    if (!(microsec = PyObject_GetAttrString(ctx->obj, "microsecond")))
        goto _unknown_error_microsec_deref_seconds;
    if (!PyLong_Check(microsec))
        goto _unknown_error_microsec_deref_microsec;
    u32 = ((uint32_t) PyLong_AsUnsignedLong(microsec)) * 1000;
    if (PyErr_Occurred())
        goto _unknown_error_microsec_deref_microsec;
    if (i64 >> 34) {
        // 96-bit timestamp
        if (packer_make_fit(ctx, 15))
            goto _no_memory_deref_microsec;
        _pack_int(ctx, 0xc7, 1);
        _pack_int(ctx, 0x0c, 1);
        _pack_int(ctx, 0xff, 1);
        _pack_int(ctx, u32, 4);
        _pack_int(ctx, (uint64_t) i64, 8);
    }
    else if (u32 || i64 >> 32) {
        // 64-bit timestamp
        if (packer_make_fit(ctx, 10))
            goto _no_memory_deref_microsec;
        u64 = (((uint64_t) u32) << 34) | ((uint64_t) i64);
        _pack_int(ctx, 0xd7, 1);
        _pack_int(ctx, 0xff, 1);
        _pack_int(ctx, u64, 8);
    }
    else {
        // 32-bit timestamp
        if (packer_make_fit(ctx, 6))
            goto _no_memory_deref_microsec;
        _pack_int(ctx, 0xd6, 1);
        _pack_int(ctx, 0xff, 1);
        _pack_int(ctx, (uint32_t) i64, 4);
    }
    Py_DECREF(microsec);
    Py_DECREF(seconds);

    return 0;

_unknown_error_seconds:
    PyErr_SetString(Error, "Unknown error occurred calling obj.timestamp().");
    goto _error;

_unknown_error_seconds_deref_seconds:
    PyErr_SetString(Error, "Unknown error occurred calling obj.timestamp().");
    goto _error_deref_seconds;

_unknown_error_microsec_deref_seconds:
    PyErr_SetString(Error, "Unknown error occurred getting obj.microsecond.");
    goto _error_deref_seconds;

_unknown_error_microsec_deref_microsec:
    PyErr_SetString(Error, "Unknown error occurred getting obj.microsecond.");
    goto _error_deref_microsec;

_no_memory_deref_microsec:
    goto _error_deref_microsec;

_error_deref_microsec:
    Py_DECREF(microsec);
_error_deref_seconds:
    Py_DECREF(seconds);
_error:
    return 1;
}


int __pack_ext(packer * ctx)
{
    int32_t _typecode, overflow;
    PyObject * tuple, * typecode, * data;
    Py_buffer pybuf;

    if (!(tuple = PyObject_GetAttrString(ctx->obj, "__msgpack__")))
        goto _unknown_error_tuple;
    if (!(PyTuple_Check(tuple) && PyTuple_GET_SIZE(tuple) == 2))
        goto _bad_type_deref_tuple;
    if (!(typecode = PyTuple_GET_ITEM(tuple, 0)))
        goto _unknown_error_typecode_deref_tuple;
    if (!PyLong_Check(typecode))
        goto _bad_typecode_deref_typecode;
    _typecode = (int32_t) PyLong_AsLongAndOverflow(typecode, &overflow);
    if (PyErr_Occurred())
        goto _unknown_error__typecode_deref_typecode;
    if (overflow || _typecode < 0 || _typecode > 127)
        goto _bad_typecode_deref_typecode;
    if (!(data = PyTuple_GET_ITEM(tuple, 1)))
        goto _unknown_error_data_deref_typecode;
    if (!PyObject_CheckBuffer(data) || PyObject_GetBuffer(data, & pybuf, 0))
        goto _bad_data_deref_data;
    // check if buffer fits and copy length to context
    if (pybuf.len < (1 << 8)) {
        if (packer_make_fit(ctx, 2 + pybuf.len))
            goto _no_memory_deref_pybuf;
        switch (pybuf.len) {
            case  1: { _pack_int(ctx, 0xd4, 1);  break; }       // fixext 1
            case  2: { _pack_int(ctx, 0xd5, 1);  break; }       // fixext 2
            case  4: { _pack_int(ctx, 0xd6, 1);  break; }       // fixext 4
            case  8: { _pack_int(ctx, 0xd7, 1);  break; }       // fixext 8
            case 16: { _pack_int(ctx, 0xd8, 1);  break; }       // fixext 16
            default: {
                if (packer_make_fit(ctx, 3 + pybuf.len))
                    goto _no_memory_deref_pybuf;
                _pack_int(ctx, 0xc7, 1);            // ext 8
                _pack_int(ctx, pybuf.len, 1);
            }
        }
    }
    else if ((uint64_t) pybuf.len < (1ULL << 16)) {
        // ext 16
        if (packer_make_fit(ctx, 4 + pybuf.len))
            goto _no_memory_deref_pybuf;
        _pack_int(ctx, 0xc8, 1);                    // ext 16
        _pack_int(ctx, pybuf.len, 2);
    }
    else if ((uint64_t) pybuf.len < (1ULL << 32)) {
        if (packer_make_fit(ctx, 6 + pybuf.len)) 
            goto _no_memory_deref_pybuf;
        _pack_int(ctx, 0xc9, 1);                    // ext 32
        _pack_int(ctx, pybuf.len, 4);
    }
    // huge ext
    else goto _value_too_big_deref_pybuf;
    // copy type to context
    _pack_int(ctx, _typecode, 1);
    // copy data to context
    if (PyBuffer_ToContiguous(
        ctx->buffer + ctx->seek, & pybuf, pybuf.len, 'C'
    ))
        goto _unknown_error_ctx_buffer_deref_pybuf;
    ctx->seek += pybuf.len;
    PyBuffer_Release(& pybuf);
    Py_DECREF(data);
    Py_DECREF(typecode);
    Py_DECREF(tuple);

    return 0;

_unknown_error_tuple:
    PyErr_SetString(Error, "Unknown error occurred getting obj.__msgpack__.");
    goto _error;

_unknown_error_typecode_deref_tuple:
    PyErr_SetString(Error, "Unknown error occurred getting typecode from tuple.");
    goto _error_deref_tuple;

_unknown_error__typecode_deref_typecode:
    PyErr_SetString(Error, "Unknown error occurred converting typecode to C long.");
    goto _error_deref_typecode;

_unknown_error_data_deref_typecode:
    PyErr_SetString(Error, "Unknown error occurred getting data from tuple.");
    goto _error_deref_typecode;

_unknown_error_ctx_buffer_deref_pybuf:
    PyErr_SetString(Error, "Unknown error occurred copying buffer to ctx->buffer.");
    goto _error_deref_pybuf;

_bad_type_deref_tuple:
    PyErr_SetString(PackError, "obj.__msgpack__ is not a valid Tuple[int, bytes] or Callable.");
    goto _error_deref_tuple;

_bad_typecode_deref_typecode:
    PyErr_SetString(PackError, "Extension object typecode must be an int in range(128).");
    goto _error_deref_typecode;

_bad_data_deref_data:
    PyErr_SetString(PackError, "Extension object data must be a readable buffer.");
    goto _error_deref_data;

_no_memory_deref_pybuf:
    goto _error_deref_pybuf;

_value_too_big_deref_pybuf:
    PyErr_SetString(PackError, "Extension object is too large to serialize.");
    goto _error_deref_pybuf;

_error_deref_pybuf:
    PyBuffer_Release(& pybuf);
_error_deref_data:
    Py_DECREF(data);
_error_deref_typecode:
    Py_DECREF(typecode);
_error_deref_tuple:
    Py_DECREF(tuple);
_error:
    return 1;
}


int packer_pack_ext(packer * ctx)
{
    if (PyObject_HasAttrString(ctx->obj, "__msgpack__"))
        return __pack_ext(ctx);
    else if (_check_pack_timestamp(ctx->obj))
        return __pack_timestamp(ctx);
    else goto _bad_type;

_bad_type:
    PyErr_SetString(PackError, "Extension object must be a timestamp or implement __msgpack__.");
    goto _error;

_error:
    return 1;
}


typedef struct {
    uint8_t * buffer;
    uint64_t seek;
    uint64_t len;
    PyObject * ext_map;
} unpacker;

unpacker * unpacker_init(PyObject * args);
void unpacker_close(unpacker * ctx);
PyObject * unpacker_unpack(unpacker * ctx);
PyObject * unpacker_unpack_nil(unpacker * ctx);
PyObject * unpacker_unpack_bool(unpacker * ctx);
PyObject * unpacker_unpack_int(unpacker * ctx);
PyObject * unpacker_unpack_float(unpacker * ctx);
PyObject * unpacker_unpack_bytes(unpacker * ctx);
PyObject * unpacker_unpack_utf8(unpacker * ctx);
PyObject * unpacker_unpack_array(unpacker * ctx);
PyObject * unpacker_unpack_map(unpacker * ctx);
PyObject * unpacker_unpack_ext(unpacker * ctx);


#define UNPACK_METHOD(pymethod, cmethod)                        \
static PyObject * pymethod(PyObject * self, PyObject * args)    \
{                                                               \
    PyObject * obj;                                             \
    unpacker * ctx = unpacker_init(args);                       \
                                                                \
    if (!ctx)                                                   \
        return NULL;                                            \
    obj = cmethod(ctx);                                         \
    unpacker_close(ctx);                                        \
                                                                \
    return obj;                                                 \
}

UNPACK_METHOD(unpack, unpacker_unpack);
UNPACK_METHOD(unpack_nil, unpacker_unpack_nil);
UNPACK_METHOD(unpack_bool, unpacker_unpack_bool);
UNPACK_METHOD(unpack_int, unpacker_unpack_int);
UNPACK_METHOD(unpack_float, unpacker_unpack_float);
UNPACK_METHOD(unpack_bytes, unpacker_unpack_bytes);
UNPACK_METHOD(unpack_utf8, unpacker_unpack_utf8);
UNPACK_METHOD(unpack_array, unpacker_unpack_array);
UNPACK_METHOD(unpack_map, unpacker_unpack_map);
UNPACK_METHOD(unpack_ext, unpacker_unpack_ext);

#undef UNPACK_METHOD


unpacker * unpacker_init(PyObject * args)
{
    PyObject * obj, * ext_map = NULL;
    Py_buffer pybuf;
    unpacker * ctx;

    if (!PyArg_ParseTuple(args, "O|O", & obj, & ext_map))
        goto _error;
    if (!PyObject_CheckBuffer(obj))
        goto _bad_buffer_type;
    if (ext_map && !PyMapping_Check(ext_map))
        goto _bad_map_type;
    if (PyObject_GetBuffer(obj, & pybuf, 0))
        goto _bad_buffer_type;
    if (!pybuf.len)
        goto _no_data_deref_pybuf;
    if (!(ctx = malloc(sizeof(unpacker))))
        goto _no_memory_deref_pybuf;
    if (!(ctx->buffer = malloc(pybuf.len)))
        goto _no_memory_deref_ctx;
    if (PyBuffer_ToContiguous(ctx->buffer, & pybuf, pybuf.len, 'C'))
        goto _bad_buffer_type_deref_buffer;
    ctx->seek = 0;
    ctx->len = pybuf.len;
    if (ext_map)
        Py_INCREF(ext_map);
    ctx->ext_map = ext_map;
    PyBuffer_Release(& pybuf);

    return ctx;

_bad_buffer_type:
    PyErr_SetString(UnpackError, "unpack input must be buffer.");
    goto _error;

_bad_buffer_type_deref_buffer:
    PyErr_SetString(UnpackError, "unpack input must be buffer.");
    goto _deref_buffer;

_bad_map_type:
    PyErr_SetString(UnpackError, "Extension callback map must be a map.");
    goto _error;

_no_memory_deref_pybuf:
    PyErr_SetString(PyErr_NoMemory(), "Out of memory.");
    goto _deref_pybuf;

_no_memory_deref_ctx:
    PyErr_SetString(PyErr_NoMemory(), "Out of memory.");
    goto _deref_ctx;

_no_data_deref_pybuf:
    PyErr_SetString(UnpackError, "Not enough input to unpack whole object.");
    goto _deref_pybuf;

_deref_buffer:
    free(ctx->buffer);
_deref_ctx:
    free(ctx);
_deref_pybuf:
    PyBuffer_Release(& pybuf);

_error:
    return NULL;
}


void unpacker_close(unpacker * ctx)
{
    if (ctx->ext_map)
        Py_DECREF(ctx->ext_map);
    if (ctx->len)
        free(ctx->buffer);
    free(ctx);

}


PyObject * unpacker_unpack(unpacker * ctx)
{
    uint8_t code;

    if (ctx->len < (ctx->seek) + 1)
        goto _no_data;
    code = ctx->buffer[ctx->seek];      // dont consume
    if ((code >> 7) == 0b0 || ((code >> 5) == 0b111))
        return unpacker_unpack_int(ctx);
    if ((code >> 5) == 0b101)
        return unpacker_unpack_utf8(ctx);
    if ((code >> 4) == 0b1001)
        return unpacker_unpack_array(ctx);
    if ((code >> 4) == 0b1000)
        return unpacker_unpack_map(ctx);
    switch (code) {
        case 0xc0: return unpacker_unpack_nil(ctx);
        case 0xc1: goto _bad_typecode;
        case 0xc2:
        case 0xc3: return unpacker_unpack_bool(ctx);
        case 0xc4:
        case 0xc5:
        case 0xc6: return unpacker_unpack_bytes(ctx);
        case 0xc7:
        case 0xc8:
        case 0xc9: return unpacker_unpack_ext(ctx);
        case 0xca:
        case 0xcb: return unpacker_unpack_float(ctx);
        case 0xcc:
        case 0xcd:
        case 0xce:
        case 0xcf:
        case 0xd0:
        case 0xd1:
        case 0xd2:
        case 0xd3: return unpacker_unpack_int(ctx);
        case 0xd4:
        case 0xd5:
        case 0xd6:
        case 0xd7:
        case 0xd8: return unpacker_unpack_ext(ctx);
        case 0xd9:
        case 0xda:
        case 0xdb: return unpacker_unpack_utf8(ctx);
        case 0xdc:
        case 0xdd: return unpacker_unpack_array(ctx);
        case 0xde:
        case 0xdf: return unpacker_unpack_map(ctx);
        default: goto _bad_typecode;
    }

_no_data:
    printf("seek: %d, len: %d\n", ctx->seek, ctx->len);
    PyErr_SetString(UnpackError, "Not enough input to unpack whole object.");
    goto _error;

_bad_typecode:
    PyErr_SetString(UnpackError, "Encountered forbidden typecode while deserializing.");
    goto _error;

_error:
    return NULL;
}


PyObject * unpacker_unpack_nil(unpacker * ctx)
{
    uint8_t code = 0;

    if (ctx->len < (ctx->seek) + 1)
        goto _insufficient_data;
    _unpack_int(code, ctx, 1);
    if (code != 0xc0)
        goto _bad_type;

    return Py_NewRef(Py_None);

_insufficient_data:
    PyErr_SetString(UnpackError, "Not enough input to unpack whole object.");
    goto _error;

_bad_type:
    PyErr_SetString(UnpackError, "Encountered bad typecode while deserializing.");
    goto _error;

_error:
    return NULL;
}


PyObject * unpacker_unpack_bool(unpacker * ctx)
{
    uint8_t code = 0;

    if (ctx->len < (ctx->seek) + 1)
        goto _insufficient_data;
    _unpack_int(code, ctx, 1);
    if (code != 0xc2 && code != 0xc3)
        goto _bad_type;

    return Py_NewRef(code == 0xc3 ? Py_True : Py_False);

_insufficient_data:
    PyErr_SetString(UnpackError, "Not enough input to unpack whole object.");
    goto _error;

_bad_type:
    PyErr_SetString(UnpackError, "Encountered bad typecode while deserializing.");
    goto _error;

_error:
    return NULL;
}


PyObject * unpacker_unpack_int(unpacker * ctx)
{
    uint8_t code = 0;
    uint8_t u8 = 0;
    uint16_t u16 = 0;
    uint32_t u32 = 0;
    uint64_t u64 = 0;

    if (ctx->len < (ctx->seek) + 1)
        goto _insufficient_data;
    _unpack_int(code, ctx, 1);
    if ((code >> 7) == 0b0)             // positive fixint
        return PyLong_FromLong(code);
    if ((code >> 5) == 0b111)           // negative fixint
        return PyLong_FromLong((int8_t) code);
    switch (code) {
        case 0xcc: {                    // uint 8
            if (ctx->len < (ctx->seek) + 1)
                goto _insufficient_data;
            _unpack_int(u8, ctx, 1);
            return PyLong_FromUnsignedLong(u8);
        }
        case 0xcd: {                    // uint 16
            if (ctx->len < (ctx->seek) + 2)
                goto _insufficient_data;
            _unpack_int(u16, ctx, 2);
            return PyLong_FromUnsignedLong(u16);
        }
        case 0xce: {                    // uint 32
            if (ctx->len < (ctx->seek) + 4)
                goto _insufficient_data;
            _unpack_int(u32, ctx, 4);
            return PyLong_FromUnsignedLong(u32);
        }
        case 0xcf: {                    // uint 64
            if (ctx->len < (ctx->seek) + 8)
                goto _insufficient_data;
            _unpack_int(u64, ctx, 8);
            return PyLong_FromUnsignedLongLong(u64);
        }
        case 0xd0: {                    // int 8
            if (ctx->len < (ctx->seek) + 1)
                goto _insufficient_data;
            _unpack_int(u8, ctx, 1);
            return PyLong_FromLong((int8_t) u8);
        }
        case 0xd1: {                    // int 16
            if (ctx->len < (ctx->seek) + 2)
                goto _insufficient_data;
            _unpack_int(u16, ctx, 2);
            return PyLong_FromLong((int16_t) u16);
        }
        case 0xd2: {                    // int 32
            if (ctx->len < (ctx->seek) + 4)
                goto _insufficient_data;
            _unpack_int(u32, ctx, 4);
            return PyLong_FromLong((int32_t) u32);
        }
        case 0xd3: {                    // int 64
            if (ctx->len < (ctx->seek) + 8)
                goto _insufficient_data;
            _unpack_int(u64, ctx, 8);
            return PyLong_FromLongLong((int64_t) u64);
        }
        default: goto _bad_type;
    }

_insufficient_data:
    PyErr_SetString(UnpackError, "Not enough input to unpack whole object.");
    goto _error;

_bad_type:
    PyErr_SetString(UnpackError, "Encountered bad typecode while deserializing.");
    goto _error;

_error:
    return NULL;
}


PyObject * unpacker_unpack_float(unpacker * ctx)
{
    uint8_t code = 0;
    float f;
    double d;
    uint32_t u32 = 0;
    uint64_t u64 = 0;

    if (ctx->len < (ctx->seek) + 1)
        goto _insufficient_data;
    _unpack_int(code, ctx, 1);
    switch (code) {
        case 0xca: {                    // float 32;
            if (ctx->len < (ctx->seek) + 4)
                goto _insufficient_data;
            _unpack_int(u32, ctx, 4);
            memcpy(& f, & u32, 4);
            return PyFloat_FromDouble(f);
        }
        case 0xcb: {                    // float 64;
            if (ctx->len < (ctx->seek) + 8)
                goto _insufficient_data;
            _unpack_int(u64, ctx, 8);
            memcpy(& d, & u64, 8);
            return PyFloat_FromDouble(d);
        }
        default: goto _bad_type;
    }

_insufficient_data:
    PyErr_SetString(UnpackError, "Not enough input to unpack whole object.");
    goto _error;

_bad_type:
    PyErr_SetString(UnpackError, "Encountered bad typecode while deserializing.");
    goto _error;

_error:
    return NULL;
}


PyObject * unpacker_unpack_bytes(unpacker * ctx)
{
    uint8_t code = 0;
    uint32_t len = 0;
    PyObject * bytes;

    if (ctx->len < (ctx->seek) + 1)
        goto _insufficient_data;
    _unpack_int(code, ctx, 1);
    switch (code) {
        case 0xc4: {                    // bin 8
            if (ctx->len < (ctx->seek) + 1)
                goto _insufficient_data;
            _unpack_int(len, ctx, 1);
            break;
        }
        case 0xc5: {                    // bin 16
            if (ctx->len < (ctx->seek) + 2)
                goto _insufficient_data;
            _unpack_int(len, ctx, 2);
            break;
        }
        case 0xc6: {                    // bin 32
            if (ctx->len < (ctx->seek) + 4)
                goto _insufficient_data;
            _unpack_int(len, ctx, 4);
            break;
        }
        default: goto _bad_type;
    }
    if (ctx->len < (ctx->seek) + len)
        goto _insufficient_data;
    bytes = PyBytes_FromStringAndSize((const char *)(ctx->buffer + (ctx->seek)), len);
    ctx->seek += len;

    return bytes;

_insufficient_data:
    PyErr_SetString(UnpackError, "Not enough input to unpack whole object.");
    goto _error;

_bad_type:
    PyErr_SetString(UnpackError, "Encountered bad typecode while deserializing.");
    goto _error;

_error:
    return NULL;
}


PyObject * unpacker_unpack_utf8(unpacker * ctx)
{
    uint8_t code = 0;
    uint32_t len = 0;
    PyObject * str;

    if (ctx->len < (ctx->seek) + 1)
        goto _insufficient_data;
    _unpack_int(code, ctx, 1);
    if ((code >> 5) == 0b101)           // fixstr
        len = code & 0x1f;
    else switch (code) {
        case 0xd9: {                    // str 8
            if (ctx->len < (ctx->seek) + 1)
                goto _insufficient_data;
            _unpack_int(len, ctx, 1);
            break;
        }
        case 0xda: {                    // str 16
            if (ctx->len < (ctx->seek) + 2)
                goto _insufficient_data;
            _unpack_int(len, ctx, 2);
            break;
        }
        case 0xdb: {                    // str 32
            if (ctx->len < (ctx->seek) + 4)
                goto _insufficient_data;
            _unpack_int(len, ctx, 4);
            break;
        }
        default: goto _bad_type;
    }
    if (ctx->len < (ctx->seek) + len)
        goto _insufficient_data;
    str = PyUnicode_FromStringAndSize((const char *)(ctx->buffer + (ctx->seek)), len);
    ctx->seek += len;

    return str;

_insufficient_data:
    PyErr_SetString(UnpackError, "Not enough input to unpack whole object.");
    goto _error;

_bad_type:
    PyErr_SetString(UnpackError, "Encountered bad typecode while deserializing.");
    goto _error;

_error:
    return NULL;
}


PyObject * unpacker_unpack_array(unpacker * ctx)
{
    uint8_t code = 0;
    uint32_t len = 0;
    PyObject * array, * item;

    if (ctx->len < (ctx->seek) + 1)
        goto _insufficient_data;
    _unpack_int(code, ctx, 1);
    if ((code >> 4) == 0b1001)          // fixarray
        len = code & 0x0f;
    else switch (code) {
        case 0xdc: {                    // array 16
            if (ctx->len < (ctx->seek) + 2)
                goto _insufficient_data;
            _unpack_int(len, ctx, 2);
            break;
        }
        case 0xdd: {                    // array 32
            if (ctx->len < (ctx->seek) + 4)
                goto _insufficient_data;
            _unpack_int(len, ctx, 4);
            break;
        }
        default: goto _bad_type;
    }
    if (!(array = PyTuple_New(len)))
        goto _unknown_error_array;
    for (uint32_t i = 0; i < len; i++) {
        if (!(item = unpacker_unpack(ctx)))
            goto _error_deref_array;
        PyTuple_SET_ITEM(array, i, item);
    }

    return array;

_unknown_error_array:
    PyErr_SetString(Error, "Unknown error occurred creating tuple to unpack array.");
    goto _error;

_insufficient_data:
    PyErr_SetString(UnpackError, "Not enough input to unpack whole object.");
    goto _error;

_bad_type:
    PyErr_SetString(UnpackError, "Encountered bad typecode while deserializing.");
    goto _error;

_error_deref_array:
    Py_DECREF(array);
_error:
    return NULL;
}


PyObject * unpacker_unpack_map(unpacker * ctx)
{
    uint8_t code = 0;
    uint32_t len = 0;
    PyObject * dict, * key, * value;

    if (ctx->len < (ctx->seek) + 1)
        goto _insufficient_data;
    _unpack_int(code, ctx, 1);
    if ((code >> 4) == 0b1000)          // fixmap
        len = code & 0x0f;
    else if (0xde == code) {            // map 16
        if (ctx->len < (ctx->seek) + 2)
            goto _insufficient_data;
        _unpack_int(len, ctx, 2);
    }
    else if (0xdf == code) {            // map 32
        if (ctx->len < (ctx->seek) + 4)
            goto _insufficient_data;
        _unpack_int(len, ctx, 4);
    }
    else goto _bad_type;
    if (!(dict = PyDict_New()))
        goto _error;
    for (uint32_t i = 0; i < len; i++) {
        if (!(key = unpacker_unpack(ctx)))
            goto _error_deref_dict;
        if (!(value = unpacker_unpack(ctx)))
            goto _error_deref_key;
        if (PyDict_SetItem(dict, key, value))
            goto _error_deref_value;
    }

    return dict;

_insufficient_data:
    PyErr_SetString(UnpackError, "Not enough input to unpack whole object.");
    goto _error;

_bad_type:
    PyErr_SetString(UnpackError, "Encountered bad typecode while deserializing.");
    goto _error;

_error_deref_value:
    Py_DECREF(value);
_error_deref_key:
    Py_DECREF(key);
_error_deref_dict:
    Py_DECREF(dict);
_error:
    return NULL;
}


PyObject * __unpack_timestamp(unpacker * ctx, uint8_t len)
{
    uint32_t u32 = 0;
    uint64_t u64 = 0;
    PyObject * value, * epoch, * delta;

    if (4 == len) {                                         // 32-bit timestamp
        _unpack_int(u32, ctx, 4);
        if (!(delta = PyDelta_FromDSU(
            ((uint64_t) u32) / (3600 * 24),
            ((uint64_t) u32) % (3600 * 24),
            0
        )))
            goto _error;
        if (!(epoch = PyDate_FromDate(1970, 1, 1)))
            goto _error_deref_delta;
    }
    else if (8 == len) {                                    // 64-bit timestamp
        _unpack_int(u64, ctx, 8);
        u32 = ((uint32_t) (u64 >> 34)) / 1000;
        if (u32 > 999999)
            goto _unsupported_timestamp;
        u64 &= (1ULL << 34) - 1;
        if (!(delta = PyDelta_FromDSU(
            u64 / (3600 * 24), u64 % (3600 * 24), u32
        )))
            goto _error;
        if (!(epoch = PyDateTime_FromDateAndTime(1970, 1, 1, 0, 0, 0, 0)))
            goto _error_deref_delta;
    }
    else if (12 == len) {                                   // 96-bit timestamp
        _unpack_int(u32, ctx, 4);
        u32 /= 1000;
        if (u32 > 999999)
            goto _unsupported_timestamp;
        _unpack_int(u64, ctx, 8);
        if (!(delta = PyDelta_FromDSU(
            u64 / (3600 * 24), u64 % (3600 * 24), u32
        )))
            goto _error;
        if (!(epoch = PyDateTime_FromDateAndTime(1970, 1, 1, 0, 0, 0, 0)))
            goto _error_deref_delta;
    }
    else goto _unsupported_timestamp;
    if (!(value = PyObject_CallMethod(epoch, "__add__", "O", delta)))
        goto _error_deref_epoch;
    Py_DECREF(epoch);
    Py_DECREF(delta);

    return value;

_unsupported_timestamp:
    PyErr_SetString(UnpackError, "Timestamp format is not supported.");
    goto _error;

_error_deref_epoch:
    Py_DECREF(epoch);
_error_deref_delta:
    Py_DECREF(delta);
_error:
    return NULL;
}


PyObject * unpacker_unpack_ext(unpacker * ctx)
{
    PyObject * value = NULL;
    uint8_t code, _type;
    uint32_t len = 0;
    PyObject * method;
    PyObject * type, * data, * tuple;

    if (ctx->len < (ctx->seek) + 1)
        goto _insufficient_data;
    _unpack_int(code, ctx, 1);
    // unpack ext length in bytes
    switch (code) {
        case 0xd4: {                    // fixext 1
            len = 1;  break;
        }
        case 0xd5: {                    // fixext 2
            len = 2;  break;
        }
        case 0xd6: {                    // fixext 4
            len = 4;  break;
        }
        case 0xd7: {                    // fixext 8
            len = 8;  break;
        }
        case 0xd8: {                    // fixext 16
            len = 16;  break;
        }
        case 0xc7: {                    // ext 8
            printf("seek: %d\n", ctx->seek);
            if (ctx->len < (ctx->seek) + 1)
                goto _insufficient_data;
            _unpack_int(len, ctx, 1);
            break;
        }
        case 0xc8: {                    // ext 16
            if (ctx->len < (ctx->seek) + 2)
                goto _insufficient_data;
            _unpack_int(len, ctx, 2);
            break;
        }
        case 0xc9: {                    // ext 32
            if (ctx->len < (ctx->seek) + 4)
                goto _insufficient_data;
            _unpack_int(len, ctx, 4);
            break;
        }
        default: goto _bad_type;
    }
    // unpack ext type
    if (ctx->len < (ctx->seek) + 1 + len) {
        goto _insufficient_data;
    }
    _unpack_int(_type, ctx, 1);
    if (_type == 0xff)
        return __unpack_timestamp(ctx, len);
    if (_type < 0 || _type > 127)
        goto _bad_type;
    // unpack application defined extension
    if (!(type = PyLong_FromLong((long) _type)))
        goto _error;
    if (!PyMapping_HasKey(ctx->ext_map, type))
        goto _bad_type_deref_type;
    if (!(data = PyBytes_FromStringAndSize(
        (const char *) (ctx->buffer + (ctx->seek)), len
    )))
        goto _error_deref_type;
    ctx->seek += len;
    if (!(tuple = PyTuple_New(2)))
        goto _error_deref_data;
    PyTuple_SET_ITEM(tuple, 0, type);
    PyTuple_SET_ITEM(tuple, 1, data);
    if (!(method = PyObject_GetItem(ctx->ext_map, type)))
        goto _error_deref_tuple;
    if (PyCallable_Check(method))
        if (!(value = PyObject_CallObject(method, tuple)))
            goto _error_deref_method;
    Py_DECREF(method);

    if (value) return value;

_insufficient_data:
    PyErr_SetString(UnpackError, "Not enough input to unpack whole object.");
    goto _error;

_bad_type:
    PyErr_SetString(UnpackError, "Object type not supported for unpacking.");
    goto _error;

_bad_type_deref_type:
    PyErr_SetString(UnpackError, "Object type not supported for unpacking.");
    goto _error_deref_type;

_error_deref_method:
    Py_DECREF(method);
_error_deref_tuple:
    Py_DECREF(tuple);
_error_deref_data:
    Py_DECREF(data);
_error_deref_type:
    Py_DECREF(type);
_error:
    return NULL;
}
