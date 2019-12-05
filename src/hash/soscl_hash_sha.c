//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
// soscl_sha.c
// implementation of the hash generic interface
// taking the hash function algo reference as a parameter
#include <soscl/soscl_hash.h>
#include <soscl/soscl_sha.h>
#include <soscl/soscl_hash_sha256.h>
#include <soscl/soscl_hash_sha384.h>
#include <soscl/soscl_hash_sha512.h>
#include <soscl/soscl_init.h>
#include <soscl/soscl_retdefs.h>

 soscl_sha256_ctx_t _soscl_hash_ctx256;
 soscl_sha384_ctx_t _soscl_hash_ctx384;
 soscl_sha512_ctx_t _soscl_hash_ctx512;
 int _soscl_hash_algo;

int soscl_sha_init(int algo)
{
  _soscl_hash_algo=algo;
  switch(algo)
    {
    case SOSCL_SHA256_ID:
      return(soscl_sha256_init(&_soscl_hash_ctx256));
      break;
    case SOSCL_SHA384_ID:
      return(soscl_sha384_init(&_soscl_hash_ctx384));
      break;
    case SOSCL_SHA512_ID:
      return(soscl_sha512_init(&_soscl_hash_ctx512));
      break;
    default:
      return(SOSCL_ERROR);
    }
}

int soscl_sha_core(uint8_t *data,int data_byte_len)
{
  switch(_soscl_hash_algo)
    {
    case SOSCL_SHA256_ID:
      return(soscl_sha256_core(&_soscl_hash_ctx256,data,data_byte_len));
      break;
    case SOSCL_SHA384_ID:
      return(soscl_sha384_core(&_soscl_hash_ctx384,data,data_byte_len));
      break;
    case SOSCL_SHA512_ID:
      return(soscl_sha512_core(&_soscl_hash_ctx512,data,data_byte_len));
      break;
    default:
      return(SOSCL_ERROR);
    }
}

int soscl_sha_finish(uint8_t *hash)
{
  switch(_soscl_hash_algo)
    {
    case SOSCL_SHA256_ID:
      return(soscl_sha256_finish(hash,&_soscl_hash_ctx256));
      break;
    case SOSCL_SHA384_ID:
      return(soscl_sha384_finish(hash,&_soscl_hash_ctx384));
      break;
    case SOSCL_SHA512_ID:
      return(soscl_sha512_finish(hash,&_soscl_hash_ctx512));
      break;
    default:
      return(SOSCL_ERROR);
    }
}

int soscl_sha(uint8_t *hash,uint8_t *data,int data_byte_len,int algo)
{

  switch(algo)
    {
    case SOSCL_SHA256_ID:
      return(soscl_sha256(hash,data,data_byte_len));
      break;
    case SOSCL_SHA384_ID:
      return(soscl_sha384(hash,data,data_byte_len));
      break;
    case SOSCL_SHA512_ID:
      return(soscl_sha512(hash,data,data_byte_len));
      break;
    default:
      return(SOSCL_ERROR);
    }
}

//this function is used to determine if a proposed integer is a valide hash digest length
//it is used in ECDSA for checking
int soscl_valid_hash_digest_length(int inputlength)
{
  if(inputlength!=SOSCL_SHA256_BYTE_HASHSIZE)
    if(inputlength!=SOSCL_SHA384_BYTE_HASHSIZE)
      if(inputlength!=SOSCL_SHA512_BYTE_HASHSIZE)
	return(SOSCL_INVALID_INPUT);
  return(SOSCL_OK);
}
