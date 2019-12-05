//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
// soscl_sha512.h
// contains definitions of structures and primitives used for SHA512 and HMAC-SHA512 implementation

#ifndef _SOSCL_SHA512_H
#define _SOSCL_SHA512_H
#ifdef __cplusplus
extern "C" {
#endif // __cplusplus
#include <soscl/soscl_config.h>
#include <soscl/soscl_defs.h>
#include <soscl/soscl_retdefs.h>
#include <soscl/soscl_types.h>
#include <soscl/soscl_init.h>
#include <soscl/soscl_hash.h>

#define SOSCL_SHA512_BYTE_BLOCKSIZE 128
#define SOSCL_SHA512_ID 3
#define SOSCL_SHA512_BYTE_HASHSIZE 64
#define SOSCL_SHA512_ROUNDS_NUMBER 80
#define SOSCL_SHA512_H_SIZE 8
  //the nb of bytes for storing the size in the last block
#define SOSCL_SHA512_BYTE_SIZE_BLOCKSIZE 16
  struct soscl_sha512_ctx
{
    // Initial, intermediate and then final hash.
    double_word_type h[SOSCL_SHA512_H_SIZE];
    // bit len
    double_word_type bitlen;
    // block buffer
    uint8_t block_buffer[SOSCL_SHA512_BYTE_BLOCKSIZE];
};

typedef struct soscl_sha512_ctx soscl_sha512_ctx_t;

  int soscl_sha512(uint8_t *hash,uint8_t *data,int data_byte_len);
  int soscl_sha512_init(soscl_sha512_ctx_t *context);
  int soscl_sha512_core(soscl_sha512_ctx_t *context,uint8_t *data,int data_byteLen);
  void soscl_sha512_block(soscl_sha512_ctx_t *ctx,uint8_t *m);
  int soscl_sha512_finish(uint8_t *hash,soscl_sha512_ctx_t *context);
  int soscl_hmac_sha512(uint8_t *mac,int mac_byte_len, uint8_t *message,int message_byte_len, uint8_t *key,int key_byte_len);
  int soscl_hmac_sha512_init(soscl_sha512_ctx_t *context , uint8_t *key, int key_byte_len);
  int soscl_hmac_sha512_core(soscl_sha512_ctx_t *context, uint8_t *data, int byte_len);
  int soscl_hmac_sha512_finish(uint8_t *mac, int mac_byte_len, soscl_sha512_ctx_t *context, uint8_t *key, int key_byte_len);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif//SOSCL_SHA512_H

