/* Copyright (C) 2014 Peter Todd <pete@petertodd.org>
**
** This file is part of Timelock.
**
** It is subject to the license terms in the LICENSE file found in the top-level
** directory of this distribution.
**
** No part of Timelock, including this file, may be copied, modified,
** propagated, or distributed except according to the terms contained in the
** LICENSE file.
*/

#include <string.h>
#include <Python.h>
#include "openssl/sha.h"

static PyObject *
sha256_run(PyObject *self, PyObject *args)
{
    unsigned PY_LONG_LONG i,n;
    const unsigned char *iv;
    unsigned char midstate[SHA256_DIGEST_LENGTH];
    Py_ssize_t iv_length;

    if (!PyArg_ParseTuple(args, "s#K", &iv, &iv_length, &n))
        return NULL;

    if (((int) iv_length) != SHA256_DIGEST_LENGTH)
        return NULL;

    memcpy(midstate, iv, SHA256_DIGEST_LENGTH);

    for (i = 0; i < n; i++) {
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, midstate, SHA256_DIGEST_LENGTH);
        SHA256_Final(midstate, &sha256);
    }

    return PyBytes_FromStringAndSize((char *)midstate, sizeof(midstate));
}

static PyMethodDef Sha256Methods[] = {
    {"run",  sha256_run, METH_VARARGS,
     "SHA256 kernel"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static struct PyModuleDef sha256module = {
   PyModuleDef_HEAD_INIT,
   "sha256",   /* name of module */
   NULL, /* module documentation, may be NULL */
   -1,       /* size of per-interpreter state of the module,
                or -1 if the module keeps state in global variables. */
   Sha256Methods
};

PyMODINIT_FUNC
PyInit_sha256(void)
{
    return PyModule_Create(&sha256module);
}
