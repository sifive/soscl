//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
// soscl_sha384.c
// implements the SHA-384 hash function explicit interface

//do not use soscl stack
#include <soscl/soscl_config.h>
#include <soscl/soscl_defs.h>
#include <soscl/soscl_retdefs.h>
#include <soscl/soscl_types.h>
#include <soscl/soscl_init.h>
#include <soscl/soscl_string.h>
#include <soscl/soscl_hash.h>
#include <soscl/soscl_hash_sha384.h>
#include <soscl/soscl_bignumbers.h>

static const double_word_type initial_h[SOSCL_SHA512_H_SIZE]={0xcbbb9d5dc1059ed8ULL,0x629a292a367cd507ULL,0x9159015a3070dd17ULL,0x152fecd8f70e5939ULL,0x67332667ffc00b31ULL,0x8eb44a8768581511ULL,0xdb0c2e0d64f98fa7ULL,0x47b5481dbefa4fa4ULL};

int soscl_sha384_init(soscl_sha384_ctx_t *ctx)
{
  int i;
  if (NULL==ctx)
    return(SOSCL_INVALID_INPUT);
  ctx->bitlen=0;
  for(i=0;i<SOSCL_SHA512_H_SIZE;i++)
    ctx->h[i]=initial_h[i];
  return(SOSCL_OK);
}

//SHA384 digest is truncation of SHA512 digest
int soscl_sha384_core(soscl_sha384_ctx_t *ctx, uint8_t *data, int data_byte_len)
{
  return(soscl_sha512_core(ctx,data,data_byte_len));
}

//compute sha512 and truncate
int soscl_sha384_finish(uint8_t *hash,soscl_sha384_ctx_t *ctx)
{
  uint8_t sha512_hash[SOSCL_SHA512_BYTE_HASHSIZE];
  int i;
  soscl_sha512_finish(sha512_hash,ctx);
  for(i=0;i<SOSCL_SHA384_BYTE_HASHSIZE;i++)
    hash[i]=sha512_hash[i];
  //cleaning the context,useful for hmac,useless for hash
  soscl_memset(ctx,0,sizeof(*ctx));
  return(SOSCL_OK);
}

int soscl_sha384(uint8_t *hash,uint8_t *data,int data_byte_len)
{
  int ret;
  soscl_sha384_ctx_t ctx;
  if (NULL==hash)
    return(SOSCL_INVALID_OUTPUT);
  if (NULL==data)
    return(SOSCL_INVALID_INPUT);
  if(SOSCL_OK!=soscl_sha384_init(&ctx))
    return(SOSCL_ERROR);
  ret=soscl_sha384_core(&ctx,data,data_byte_len);
  if(SOSCL_OK==ret)
    ret=soscl_sha384_finish(hash,&ctx);
  return(ret);
}
