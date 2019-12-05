//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
// soscl_sha256.h
// contains definitions of structures and primitives used for SHA256 and HMAC-SHA256 implementation

#ifndef _SOSCL_SHA256_H
#define _SOSCL_SHA256_H

#include <soscl/soscl_config.h>
#include <soscl/soscl_defs.h>
#include <soscl/soscl_retdefs.h>
#include <soscl/soscl_types.h>
#include <soscl/soscl_init.h>
#include <soscl/soscl_hash.h>

#ifdef __cplusplus
extern "C" {
#endif // _ cplusplus

#define SOSCL_SHA256_BYTE_BLOCKSIZE 64
#define SOSCL_SHA256_ID 1
#define SOSCL_SHA256_BYTE_HASHSIZE 32
#define SOSCL_SHA256_ROUNDS_NUMBER 64
#define SOSCL_SHA256_H_SIZE 8
  //the nb of bytes for storing the size in the last block
#define SOSCL_SHA256_BYTE_SIZE_BLOCKSIZE 8
  struct soscl_sha256_ctx
  {
    // intermediate state and then final hash
    word_type h[SOSCL_SHA256_H_SIZE];
    // bits length
    double_word_type bitlen;
    // block buffer
    uint8_t block_buffer[SOSCL_SHA256_BYTE_BLOCKSIZE];
  };
  
typedef struct soscl_sha256_ctx soscl_sha256_ctx_t;

  int soscl_sha256(uint8_t *hash, uint8_t *data, int data_byte_len);
  int soscl_sha256_init(soscl_sha256_ctx_t *context);
  int soscl_sha256_core(soscl_sha256_ctx_t *context, uint8_t *data, int data_byte_len);
  void soscl_sha256_block(soscl_sha256_ctx_t *context,uint8_t *m);
  int soscl_sha256_finish(uint8_t *hash, soscl_sha256_ctx_t *context);

  int soscl_hmac_sha256(uint8_t *mac,int mac_byte_len, uint8_t *message,int message_byte_len, uint8_t *key,int key_byte_len);
  int soscl_hmac_sha256_init(soscl_sha256_ctx_t *context , uint8_t *key, int key_byte_len);
  int soscl_hmac_sha256_core(soscl_sha256_ctx_t *context, uint8_t *data, int byte_len);
  int soscl_hmac_sha256_finish(uint8_t *mac, int mac_byte_len, soscl_sha256_ctx_t *context, uint8_t *key, int key_byte_len);
  
#ifdef __cplusplus
}
#endif // _ cplusplus
#endif // _SOSCL_SHA256_H
