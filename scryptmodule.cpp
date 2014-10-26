#include <Python.h>

#include "scrypt.h"

const unsigned char minNfactor = 5;
const unsigned char maxNfactor = 13;
const unsigned char nFactorDiff = (maxNfactor - minNfactor);
static int64 aptCoinStartTime = 1408316143;
static const int64 ONE_YEAR_IN_SECONDS = 31536000;
static const int64 TWO_YEARS_IN_SECONDS = (2 * ONE_YEAR_IN_SECONDS);

unsigned char GetNfactor(unsigned int hashPrevBlock, int64 blockTime)
{   
  int64 elapsedTime = 0;
  unsigned char timeAdjustment = 0;
  unsigned char nDiff = (maxNfactor - minNfactor);
  unsigned char nFactor = minNfactor;

  if ((aptCoinStartTime != -1) && (blockTime >= aptCoinStartTime))
  {
    elapsedTime = (blockTime - aptCoinStartTime);
    // increment the step adjustment by one for roughly every 2 years                                                                                               
    if ((elapsedTime % TWO_YEARS_IN_SECONDS) == 0)
    {   
      timeAdjustment = (unsigned char)(elapsedTime / TWO_YEARS_IN_SECONDS);
    }
    nFactor = (hashPrevBlock % (nDiff + timeAdjustment)) + minNfactor;
  }
  return nFactor;
}

static inline uint32_t swab32(uint32_t v)
{
  return __builtin_bswap32(v);
}

static inline unsigned int convert_prev_hash(unsigned char *hash_prev_block)
{
  unsigned int hpb = (unsigned int)swab32(*((uint32_t *)&hash_prev_block[28]));
  return hpb;
}

static PyObject *scryptnm_getpowhash(PyObject *self, PyObject *args)
{
    char *output;
    PyObject *value;
#if PY_MAJOR_VERSION >= 3
    PyBytesObject *input;
#else
    PyStringObject *input;
#endif
    int64 ntime;
    const char *prevhash_str;

    if (!PyArg_ParseTuple(args, "SsL", &input, &prevhash_str, &ntime))
        return NULL;
    Py_INCREF(input);
    Py_INCREF(&prevhash_str);
    Py_INCREF(&ntime);
    output = (char *)PyMem_Malloc(32);

    uint256 prevhash_tmp;
    prevhash_tmp.SetHex(prevhash_str);

    unsigned int hpb = GET_HPB(prevhash_tmp);
    unsigned char nFactor = GetNfactor(hpb, ntime);
    unsigned long int scrypt_scratchpad_size_current_block = ((1 << (nFactor + 1)) * 128 ) + 63;
    char *scratchpad = (char *)malloc(scrypt_scratchpad_size_current_block);

#if PY_MAJOR_VERSION >= 3
    scrypt_N_1_1_256_sp_generic((char *)PyBytes_AsString((PyObject*) input), output, scratchpad, nFactor);
#else
    scrypt_N_1_1_256_sp_generic((char *)PyString_AsString((PyObject*) input), output, scratchpad, nFactor);
#endif
    Py_DECREF(input);
    Py_DECREF(&prevhash_str);
    Py_DECREF(&ntime);
#if PY_MAJOR_VERSION >= 3
    value = Py_BuildValue("y#", output, 32);
#else
    value = Py_BuildValue("s#", output, 32);
#endif

    free(scratchpad);
    PyMem_Free(output);
    return value;
}

static PyMethodDef ScryptNMMethods[] = {
    { "getPoWHash", scryptnm_getpowhash, METH_VARARGS, "Returns the proof of work hash using scrypt-nm" },
    { NULL, NULL, 0, NULL }
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef ScryptNMModule = {
    PyModuleDef_HEAD_INIT,
    "apt_scrypt",
    "...",
    -1,
    ScryptNMMethods
};

PyMODINIT_FUNC PyInit_ltc_scrypt(void) {
    return PyModule_Create(&ScryptNMModule);
}

#else

PyMODINIT_FUNC initapt_scrypt(void) {
    (void) Py_InitModule("apt_scrypt", ScryptNMMethods);
}
#endif
