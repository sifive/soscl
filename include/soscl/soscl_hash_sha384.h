//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
// soscl_sha384.h
// contains definitions of structures and primitives used for SHA384 and HMAC-SHA384 implementation

#ifndef _SOSCL_SHA384_H
#define _SOSCL_SHA384_H
#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include <soscl/soscl_config.h>
#include <soscl/soscl_defs.h>
#include <soscl/soscl_retdefs.h>
#include <soscl/soscl_types.h>
#include <soscl/soscl_init.h>
#include <soscl/soscl_hash.h>

  //because SHA384 is a truncation of SHA512
#include <soscl/soscl_hash_sha512.h>
typedef struct soscl_sha512_ctx soscl_sha384_ctx_t;
  
#define SOSCL_SHA384_BYTE_BLOCKSIZE 128
#define SOSCL_SHA384_ID 2
#define SOSCL_SHA384_BYTE_HASHSIZE 48

  int soscl_sha384(uint8_t *hash, uint8_t *data, int data_byte_len);
  int soscl_sha384_init(soscl_sha384_ctx_t *context);
  int soscl_sha384_core(soscl_sha384_ctx_t *context, uint8_t *data, int data_byte_len);
  int soscl_sha384_finish(uint8_t *hash, soscl_sha384_ctx_t *context);
  int soscl_hmac_sha384(uint8_t *mac,int mac_byte_len, uint8_t *message,int message_byte_len, uint8_t *key,int key_byte_len);
  int soscl_hmac_sha384_init(soscl_sha384_ctx_t *context , uint8_t *key, int key_byte_len);
  int soscl_hmac_sha384_core(soscl_sha384_ctx_t *context, uint8_t *data, int byte_len);
  int soscl_hmac_sha384_finish(uint8_t *mac, int mac_byte_len, soscl_sha384_ctx_t *context, uint8_t *key, int key_byte_len);
#ifdef __cplusplus
}
#endif // __cplusplus
#endif//_SOSCL_SHA384_H
