//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
//soscl_sha.h
// defines the generic hash function interface, where the hash function is transmitted as a parameter.

#ifndef _SOSCL_HASH_H
#define _SOSCL_HASH_H
#ifdef __cplusplus
extern "C" {
#endif // _ cplusplus

#include <soscl/soscl_config.h>
#include <soscl/soscl_defs.h>
#include <soscl/soscl_retdefs.h>
#include <soscl/soscl_types.h>
#include <soscl/soscl_init.h>
#include <soscl/soscl_hash.h>

int soscl_sha(uint8_t *hash, uint8_t *data, int data_byte_len,int algo);
int soscl_sha_init(int algo);
int soscl_sha_core(uint8_t *data, int data_byte_len);
int soscl_sha_finish(uint8_t *hash);
int soscl_valid_hash_digest_length(int inputlength);
#ifdef __cplusplus
}
#endif // _ cplusplus

#endif//_SOSCL_HASH_H
