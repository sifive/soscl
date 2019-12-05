//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

// soscl_ecdsa.h
// contains primitives definitions for ECDSA signatures computations

#ifndef _SOSCL_ECDSA_H
#define _SOSCL_ECDSA_H
#ifdef __cplusplus
extern "C" {
#endif // __cplusplus
#include "soscl/soscl_config.h"
#include "soscl/soscl_types.h"
#include "soscl/soscl_bignumbers.h"
#include "soscl/soscl_ecc.h"

  //configuration value structure
  /*
 31...                 4 3 2 1 0
+-------------------------------+
|.....................|i|i|h|h|h|
+-------------------------------+
i bits for input type (2 bits for input type)
h bits for hash type (3 bits because of many hash functions)

the configuration is used to provide some information about the message type and the hash function

  */
#define SOSCL_HASH_INPUT_TYPE 0//message is already hashed
#define SOSCL_MSG_INPUT_TYPE 1//message has to be hashed first
#define SOSCL_HASH_FIPS_INPUT_TYPE 2//message already hashed and hash length shall match FIPS constraint, see FIPS 186-4 section 6.4
#define SOSCL_INPUT_MASK 3//so 2 bits (value 3 RFU)

#define SOSCL_HASH_MASK 7//so 3 bits: the value is the hash ID as defined in the soscl_hash_<hash-function>.h
#define SOSCL_HASH_SHIFT 0//so bits 0,1 and 2
#define SOSCL_INPUT_SHIFT 3// so bits 3 and 4

int soscl_ecdsa_signature(soscl_type_ecdsa_signature signature,uint8_t *d,int(*soscl_hash)(uint8_t*,uint8_t*,int),uint8_t *input, int inputlength, soscl_type_curve *curve_params,int configuration);
int soscl_ecdsa_verification(soscl_type_ecc_uint8_t_affine_point Q,soscl_type_ecdsa_signature signature,int(*soscl_hash)(uint8_t*,uint8_t*,int),uint8_t *input,int inputlength,soscl_type_curve *curve_params,int configuration);
#ifdef __cplusplus
}
#endif // __cplusplus
#endif//SOSCL_ECDSA_H
